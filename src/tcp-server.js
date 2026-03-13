'use strict';

/**
 * src/tcp-server.js
 * ─────────────────────────────────────────────────────────────────
 * Servidor TCP — protocolo Wialon Retranslator binario.
 *
 * Se detectaron DOS tipos de paquete en producción:
 *
 * TIPO A — magic 0x00 0x02 (paquete GPS estándar Wialon Retranslator)
 *   [0-1]    Magic: 0x00 0x02
 *   [2-5]    MsgLen   (uint32 LE)
 *   [6-9]    Timestamp (uint32 LE, unix epoch)
 *   [10-13]  Flags / señal
 *   [14+]    UnitId   null-terminated ASCII
 *   [pos+0]  Lat      (int32 LE, grados × 1e7)
 *   [pos+4]  Lon      (int32 LE, grados × 1e7)
 *   [pos+8]  Speed    (uint16 LE, km/h)
 *   [pos+10] Heading  (uint16 LE, grados 0-359)
 *   [pos+12] Flags    (bit0 = ignición)
 *
 * TIPO B — cualquier otro magic (telemetría CAN / atributos Wialon IPS)
 *   [0-3]   Header / type bytes (varía: 49 02, 7a 03, 74 04…)
 *   [4+]    UnitId  null-terminated ASCII  ← IMEI COMPLETO
 *   Resto:  atributos CAN/sensor en formato propietario — SIN datos GPS válidos
 *   → Se extrae solo el unitId para identificar la unidad; lat/lon/speed = null
 *
 * Búsqueda de unidad en BD (orden de prioridad):
 *   1. IMEI exacto
 *   2. Patente exacta
 *   3. IMEI termina con el unitId recibido (Wialon a veces envía sufijo)
 * ─────────────────────────────────────────────────────────────────
 */

const net      = require('net');
const { pool } = require('./db/pool');

const TCP_PORT = parseInt(process.env.TCP_PORT || '9001', 10);

// ── Parseo ────────────────────────────────────────────────────────

function parseWialonPacket(buf) {
  try {
    if (buf.length < 10) return null;

    const isTypeA = (buf[0] === 0x00 && buf[1] === 0x02);
    return isTypeA ? parseTypeA(buf) : parseTypeB(buf);

  } catch (e) {
    console.error('[tcp] Error parseando:', e.message,
      '— hex:', buf.toString('hex').slice(0, 60));
    return null;
  }
}

/**
 * Tipo A: magic 0x00 0x02 — GPS estándar Wialon Retranslator.
 * Contiene coordenadas lat/lon/speed/heading válidas.
 */
function parseTypeA(buf) {
  if (buf.length < 14) return null;

  const ts = buf.readUInt32LE(6);

  let idEnd = 14;
  while (idEnd < buf.length && buf[idEnd] !== 0x00) idEnd++;
  const unitId   = buf.slice(14, idEnd).toString('utf8').trim();
  const posStart = idEnd + 1;

  if (buf.length < posStart + 13) {
    // Heartbeat sin posición
    return { unitId, ts, lat: null, lon: null, speed: null,
             heading: null, ignition: null, raw: buf.toString('hex') };
  }

  const latRaw  = buf.readInt32LE(posStart);
  const lonRaw  = buf.readInt32LE(posStart + 4);
  const speed   = buf.readUInt16LE(posStart + 8);
  const heading = buf.readUInt16LE(posStart + 10);
  const flags   = buf[posStart + 12];
  const ignition = !!(flags & 0x01);

  const lat = latRaw / 1e7;
  const lon = lonRaw / 1e7;

  if (lat < -90 || lat > 90 || lon < -180 || lon > 180) {
    console.warn(`[tcp][TipoA] Coords fuera de rango: lat:${lat} lon:${lon} — unitId:${unitId}`);
    return { unitId, ts, lat: null, lon: null, speed, heading, ignition,
             raw: buf.toString('hex') };
  }

  // Validar speed y heading
  const speedOk   = speed >= 0 && speed <= 300;
  const headingOk = heading >= 0 && heading <= 360;
  console.log(`[tcp][TipoA] OK: ${unitId} lat:${lat} lon:${lon} speed:${speed}${!speedOk?' (inválida)':''}`);
  return {
    unitId, ts,
    lat, lon,
    speed:   speedOk   ? speed   : null,
    heading: headingOk ? heading : null,
    ignition,
    raw: null,
  };
}

/**
 * Tipo B: magic distinto — paquete de telemetría CAN / atributos Wialon IPS.
 * El IMEI viene desde el byte 4, pero el resto del payload NO contiene
 * datos GPS interpretables — solo se extrae el unitId para registrar
 * actividad del dispositivo.
 */
function parseTypeB(buf) {
  if (buf.length < 8) return null;

  let idEnd = 4;
  while (idEnd < buf.length && buf[idEnd] !== 0x00) idEnd++;
  const unitId = buf.slice(4, idEnd).toString('utf8').trim();

  console.log(`[tcp][TipoB] Telemetría CAN: unitId:${unitId} (sin GPS)`);
  return {
    unitId,
    ts:       Math.floor(Date.now() / 1000),  // timestamp de recepción
    lat:      null,
    lon:      null,
    speed:    null,
    heading:  null,
    ignition: null,
    raw:      buf.toString('hex'),
  };
}

function buildAck() {
  return Buffer.from([0x11, 0x22, 0x33, 0x44]);
}

// ── Buscar unidad en BD ───────────────────────────────────────────

async function findUnit(unitId) {
  if (!unitId) return null;
  const { rows } = await pool.query(
    `SELECT plate, imei FROM public.units
     WHERE UPPER(imei)  = UPPER($1)
        OR UPPER(plate) = UPPER($1)
        OR (LENGTH($1) >= 4 AND imei LIKE '%' || $1)
     ORDER BY
       CASE WHEN UPPER(imei)  = UPPER($1) THEN 0
            WHEN UPPER(plate) = UPPER($1) THEN 1
            ELSE 2 END
     LIMIT 1`,
    [unitId]
  );
  return rows[0] || null;
}

// ── Guardar evento en Supabase ────────────────────────────────────

async function saveEvent(parsed) {
  try {
    const unit  = await findUnit(parsed.unitId);
    const plate = unit?.plate || parsed.unitId;
    const imei  = unit?.imei  || null;

    if (!unit) {
      console.warn(`[tcp] Sin match en BD para unitId:"${parsed.unitId}" — guardando raw`);
    }

    await pool.query(
      `INSERT INTO public.gps_events
         (plate, imei, lat, lon, speed, heading, ignition, wialon_ts, received_at, raw_hex)
       VALUES ($1,$2,$3,$4,$5,$6,$7, to_timestamp($8), now(), $9)`,
      [
        plate, imei,
        parsed.lat, parsed.lon,
        parsed.speed, parsed.heading,
        parsed.ignition,
        parsed.ts,
        parsed.raw,
      ]
    );

    const coords = parsed.lat != null
      ? `lat:${parsed.lat} lon:${parsed.lon} speed:${parsed.speed} ign:${parsed.ignition}`
      : 'sin GPS';
    console.log(`[tcp] ✓ Guardado: ${plate} | ${coords}`);
    return plate;

  } catch (e) {
    console.error('[tcp] Error guardando en BD:', e.message);
    return parsed.unitId;
  }
}

// ── Reenviar a destinos ───────────────────────────────────────────

async function forwardToDestinations(plate, parsed) {
  // Solo reenviar si hay coordenadas GPS válidas
  if (!parsed.lat || !parsed.lon) return;

  let destinations = [];
  try {
    const { rows } = await pool.query(
      `SELECT d.api_url, d.name
       FROM public.destinations d
       WHERE d.enabled = true
         AND EXISTS (
           SELECT 1 FROM public.units u
           WHERE UPPER(u.plate) = UPPER($1)
             AND u.destinations @> jsonb_build_array(
                   jsonb_build_object('destination_id', d.id::text)
                 )
         )`,
      [plate]
    );
    destinations = rows;
  } catch {
    // Fallback: todos los destinos activos
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

  if (!destinations.length) return;

  const token = process.env.SKYNAV_TOKEN;
  if (!token) {
    console.warn('[tcp] SKYNAV_TOKEN no configurado — omitiendo reenvío');
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
        body:   JSON.stringify(payload),
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
      console.log(`[tcp] Buffer raw (${buffer.length}b): ${buffer.toString('hex').slice(0, 120)}`);

      const parsed = parseWialonPacket(buffer);
      buffer = Buffer.alloc(0);

      if (!parsed) {
        console.warn('[tcp] Paquete no parseable, ignorado.');
        return;
      }

      socket.write(buildAck());

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
