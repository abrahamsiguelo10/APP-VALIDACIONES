/**
 * src/tcp-server.js
 * ─────────────────────────────────────────────────────────────────
 * Servidor TCP que recibe paquetes del protocolo Wialon Retranslator
 * enviados por el servidor Wialon (retranslator configurado en la
 * plataforma Wialon).
 *
 * Flujo por paquete:
 *   1. Recibe buffer binario Wialon Retranslator
 *   2. Decodifica campos: plate/imei, lat, lon, speed, ignition, heading, ts
 *   3. Guarda en public.gps_events (Supabase/PostgreSQL)
 *   4. Reenvía a cada destino activo en public.destinations (Skynav)
 *   5. Responde ACK al cliente TCP (Wialon espera respuesta)
 *
 * Protocolo Wialon Retranslator v1:
 *   Header (14 bytes):
 *     [0-1]   Magic: 0x00 0x02
 *     [2-5]   Message length (uint32 LE, NO incluye los primeros 2 bytes)
 *     [6-9]   Timestamp (uint32 LE, Unix epoch UTC)
 *     [10-13] Signal quality / reserved
 *   Luego campos de longitud variable:
 *     ID de unidad (hasta primer 0x00)
 *     Datos de posición (lat/lon/speed/heading en formato binario)
 *
 * Nota: como el formato exacto puede variar según la versión configurada
 * en Wialon, incluimos parseo defensivo y logging de buffers crudos para
 * ajustar fácilmente en campo.
 * ─────────────────────────────────────────────────────────────────
 */

'use strict';

const net  = require('net');
const { pool } = require('./db/pool');

const TCP_PORT = parseInt(process.env.TCP_PORT || '9000', 10);

// ── Parseo Wialon Retranslator ────────────────────────────────────

/**
 * Intenta parsear un buffer Wialon Retranslator.
 * Devuelve null si el buffer es muy corto o tiene magic incorrecto.
 *
 * Estructura básica:
 *   Bytes 0-1   : magic 0x00 0x02
 *   Bytes 2-5   : longitud del mensaje (uint32 LE)
 *   Bytes 6-9   : timestamp Unix (uint32 LE)
 *   Bytes 10-13 : flags / señal
 *   Bytes 14+   : id de unidad (null-terminated string)
 *   Después del id: bloque de datos de posición
 *
 * El bloque de posición (Wialon Retranslator v1):
 *   4 bytes : latitud  (int32 LE, grados * 1e7)
 *   4 bytes : longitud (int32 LE, grados * 1e7)
 *   2 bytes : velocidad km/h (uint16 LE)
 *   2 bytes : heading grados (uint16 LE)
 *   1 byte  : flags (bit 0 = ignición)
 *   [resto] : sensores adicionales opcionales
 */
function parseWialonPacket(buf) {
  try {
    if (buf.length < 14) return null;

    // Magic check
    if (buf[0] !== 0x00 || buf[1] !== 0x02) {
      // Algunos firmwares omiten el magic — intentamos parsear igual
      console.warn('[tcp] Magic inesperado:', buf[0].toString(16), buf[1].toString(16));
    }

    const msgLen   = buf.readUInt32LE(2);
    const ts       = buf.readUInt32LE(6);   // Unix epoch UTC
    // const flags = buf.readUInt32LE(10);  // reservado

    // Extraer ID de unidad (null-terminated desde byte 14)
    let idEnd = 14;
    while (idEnd < buf.length && buf[idEnd] !== 0x00) idEnd++;
    const unitId = buf.slice(14, idEnd).toString('utf8').trim();

    // Bloque de posición empieza después del null-terminator
    const posStart = idEnd + 1;
    if (buf.length < posStart + 13) {
      // Paquete sin datos de posición (heartbeat / solo ID)
      return { unitId, ts, lat: null, lon: null, speed: null, heading: null, ignition: null, raw: buf.toString('hex') };
    }

    const latRaw  = buf.readInt32LE(posStart);
    const lonRaw  = buf.readInt32LE(posStart + 4);
    const speed   = buf.readUInt16LE(posStart + 8);
    const heading = buf.readUInt16LE(posStart + 10);
    const posFl   = buf[posStart + 12];
    const ignition = !!(posFl & 0x01);

    const lat = latRaw  / 1e7;
    const lon = lonRaw  / 1e7;

    // Validación básica de coordenadas
    if (lat < -90 || lat > 90 || lon < -180 || lon > 180) {
      console.warn('[tcp] Coordenadas fuera de rango:', lat, lon, '— unitId:', unitId);
      return { unitId, ts, lat: null, lon: null, speed, heading, ignition, raw: buf.toString('hex') };
    }

    return { unitId, ts, lat, lon, speed, heading, ignition, raw: null };

  } catch (e) {
    console.error('[tcp] Error parseando paquete:', e.message, '— hex:', buf.toString('hex').slice(0, 60));
    return null;
  }
}

/**
 * Construye el ACK de respuesta que Wialon espera.
 * ACK Wialon Retranslator: 4 bytes 0x11 0x22 0x33 0x44
 */
function buildAck() {
  return Buffer.from([0x11, 0x22, 0x33, 0x44]);
}

// ── Guardar en Supabase ───────────────────────────────────────────

async function saveEvent(parsed) {
  try {
    // Buscar patente en tabla units por IMEI o por el ID tal como viene
    // unitId puede ser IMEI o patente según config del retranslador en Wialon
    const { rows } = await pool.query(
      `SELECT plate, imei FROM public.units
       WHERE UPPER(imei) = UPPER($1) OR UPPER(plate) = UPPER($1)
       LIMIT 1`,
      [parsed.unitId]
    );

    const plate = rows[0]?.plate || parsed.unitId;
    const imei  = rows[0]?.imei  || null;

    await pool.query(
      `INSERT INTO public.gps_events
         (plate, imei, lat, lon, speed, heading, ignition, wialon_ts, received_at, raw_hex)
       VALUES ($1,$2,$3,$4,$5,$6,$7,
               to_timestamp($8),
               now(),
               $9)`,
      [
        plate,
        imei,
        parsed.lat,
        parsed.lon,
        parsed.speed,
        parsed.heading,
        parsed.ignition,
        parsed.ts,
        parsed.raw,
      ]
    );

    console.log(`[tcp] ✓ Guardado: ${plate} | lat:${parsed.lat} lon:${parsed.lon} speed:${parsed.speed} ign:${parsed.ignition}`);
    return plate;

  } catch (e) {
    console.error('[tcp] Error guardando en BD:', e.message);
    return parsed.unitId;
  }
}

// ── Reenviar a destinos (Skynav) ──────────────────────────────────

async function forwardToDestinations(plate, parsed) {
  if (!parsed.lat || !parsed.lon) return; // Sin coordenadas, no reenviar

  let destinations = [];
  try {
    const { rows } = await pool.query(
      `SELECT d.api_url, d.name, d.field_schema
       FROM public.destinations d
       JOIN public.units u ON u.plate = $1
       JOIN LATERAL (
         SELECT 1 FROM jsonb_array_elements_text(
           COALESCE((SELECT assigned_destinations FROM public.unit_destinations WHERE unit_plate=$1 LIMIT 1), '[]')
         ) aid WHERE aid = d.id::text
       ) x ON true
       WHERE d.enabled = true`,
      [plate]
    );
    destinations = rows;
  } catch {
    // Si no hay tabla unit_destinations o falla, intentar con todos los destinos activos
    try {
      const { rows } = await pool.query(
        `SELECT api_url, name FROM public.destinations WHERE enabled = true`
      );
      destinations = rows;
    } catch (e2) {
      console.error('[tcp] Error obteniendo destinos:', e2.message);
      return;
    }
  }

  const token = process.env.SKYNAV_TOKEN;
  if (!token) {
    console.warn('[tcp] SKYNAV_TOKEN no configurado — no se reenvía a destinos');
    return;
  }

  const payload = {
    plate,
    imei:      parsed.unitId,
    lat:       parsed.lat,
    lon:       parsed.lon,
    speed:     parsed.speed,
    heading:   parsed.heading,
    ignition:  parsed.ignition,
    timestamp: new Date(parsed.ts * 1000).toISOString(),
  };

  for (const dest of destinations) {
    if (!dest.api_url) continue;
    try {
      const res = await fetch(dest.api_url, {
        method:  'POST',
        headers: {
          'Content-Type':  'application/json',
          'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(8000),
      });
      console.log(`[tcp] → ${dest.name || dest.api_url}: ${res.status}`);
    } catch (e) {
      console.error(`[tcp] Error reenviando a ${dest.name || dest.api_url}:`, e.message);
    }
  }
}

// ── Servidor TCP ──────────────────────────────────────────────────

function startTcpServer() {
  const server = net.createServer((socket) => {
    const remote = `${socket.remoteAddress}:${socket.remotePort}`;
    console.log(`[tcp] Conexión entrante: ${remote}`);

    let buffer = Buffer.alloc(0);

    socket.on('data', async (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);

      // Log del buffer crudo (primeros 60 bytes hex) para debugging inicial
      console.log(`[tcp] Buffer raw (${buffer.length}b): ${buffer.toString('hex').slice(0, 120)}`);

      const parsed = parseWialonPacket(buffer);
      buffer = Buffer.alloc(0); // Reset buffer tras procesar

      if (!parsed) {
        console.warn('[tcp] Paquete no parseable, ignorado.');
        return;
      }

      // Responder ACK inmediatamente
      socket.write(buildAck());

      // Guardar y reenviar en background
      const plate = await saveEvent(parsed);
      if (parsed.lat && parsed.lon) {
        forwardToDestinations(plate, parsed).catch(e =>
          console.error('[tcp] Error en forward:', e.message)
        );
      }
    });

    socket.on('error', (e) => {
      console.error(`[tcp] Socket error (${remote}):`, e.message);
    });

    socket.on('close', () => {
      console.log(`[tcp] Conexión cerrada: ${remote}`);
    });

    // Timeout de inactividad: 5 minutos
    socket.setTimeout(5 * 60 * 1000);
    socket.on('timeout', () => {
      console.warn(`[tcp] Timeout inactividad: ${remote}`);
      socket.destroy();
    });
  });

  server.on('error', (e) => {
    console.error('[tcp] Error servidor TCP:', e.message);
  });

  server.listen(TCP_PORT, '0.0.0.0', () => {
    console.log(`✓ TCP Wialon Retranslator escuchando en puerto ${TCP_PORT}`);
  });

  return server;
}

module.exports = { startTcpServer };
