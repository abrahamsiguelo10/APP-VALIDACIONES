'use strict';

/**
 * src/tcp-server.js
 * ─────────────────────────────────────────────────────────────────
 * Servidor TCP — protocolo Wialon Retranslator (especificación oficial).
 *
 * Estructura del paquete:
 *   [0-3]    Packet size  (uint32 LITTLE-ENDIAN, excluye este campo)
 *   [4+]     UID          null-terminated ASCII string
 *   [pos+0]  Timestamp    (uint32 BIG-ENDIAN, unix epoch UTC)
 *   [pos+4]  Bitmask      (uint32 BIG-ENDIAN)
 *   [pos+8+] Bloques de datos (mientras queden bytes)
 *
 * Estructura de cada bloque:
 *   [0-1]  Block type   uint16 BE  (siempre 0x0BBB)
 *   [2-5]  Block size   uint32 BE  (excluye type y este campo)
 *   [6]    Stealth      byte
 *   [7]    Data type    byte       (0x01=string 0x02=binary 0x03=int 0x04=double 0x05=long)
 *   [8+]   Block name   null-terminated ASCII
 *   [n+]   Value        según data type
 *
 * Bloque posinfo (data type 0x02, nombre "posinfo"):
 *   [0-7]   Longitude  double LITTLE-ENDIAN
 *   [8-15]  Latitude   double LITTLE-ENDIAN
 *   [16-23] Altitude   double LITTLE-ENDIAN
 *   [24-25] Speed      uint16 BIG-ENDIAN  (km/h)
 *   [26-27] Course     uint16 BIG-ENDIAN  (0-359°)
 *   [28]    Satellites byte
 * ─────────────────────────────────────────────────────────────────
 */

const net      = require('net');
const { pool } = require('./db/pool');

const TCP_PORT = parseInt(process.env.TCP_PORT || '9001', 10);

// ── Parser principal ──────────────────────────────────────────────

function parseWialonPacket(buf) {
  try {
    if (buf.length < 14) return null;

    let pos = 0;

    // Packet size (uint32 LE) — solo para validación
    const pktSize = buf.readUInt32LE(pos); pos += 4;
    if (pktSize === 0 || pktSize > 65536) {
      console.warn('[tcp] Packet size inválido:', pktSize);
      return null;
    }

    // UID null-terminated
    let uidEnd = pos;
    while (uidEnd < buf.length && buf[uidEnd] !== 0x00) uidEnd++;
    const unitId = buf.slice(pos, uidEnd).toString('ascii').trim();
    pos = uidEnd + 1;

    if (!unitId) {
      console.warn('[tcp] UID vacío, paquete ignorado');
      return null;
    }

    if (buf.length < pos + 8) return null;

    // Timestamp (uint32 BE)
    const ts = buf.readUInt32BE(pos); pos += 4;

    // Bitmask (uint32 BE)
    const bitmask = buf.readUInt32BE(pos); pos += 4;

    // Leer bloques buscando "posinfo"
    let lat = null, lon = null, speed = null, heading = null, ignition = null;

    while (pos + 6 < buf.length) {
      const blkType = buf.readUInt16BE(pos); pos += 2;

      if (blkType !== 0x0BBB) {
        // Bloque desconocido — intentar saltar limpiamente
        console.warn('[tcp] Block type inesperado:', '0x'+blkType.toString(16), '— saltando');
        break;
      }

      const blkSize = buf.readUInt32BE(pos); pos += 4;
      if (blkSize === 0 || pos + blkSize > buf.length) break;

      const blk      = buf.slice(pos, pos + blkSize);
      pos           += blkSize;

      // stealth(1) + dataType(1) + name(null-term) + value
      if (blk.length < 3) continue;
      const dataType = blk[1];

      let nameEnd = 2;
      while (nameEnd < blk.length && blk[nameEnd] !== 0x00) nameEnd++;
      const blockName = blk.slice(2, nameEnd).toString('ascii');
      const valBuf    = blk.slice(nameEnd + 1);

      if (blockName === 'posinfo' && dataType === 0x02) {
        if (valBuf.length < 29) continue;

        lon           = valBuf.readDoubleLE(0);
        lat           = valBuf.readDoubleLE(8);
        const alt     = valBuf.readDoubleLE(16);
        speed         = valBuf.readUInt16BE(24);
        heading       = valBuf.readUInt16BE(26);
        const sats    = valBuf[28];

        console.log(`[tcp] posinfo: lat:${lat} lon:${lon} alt:${alt} speed:${speed} course:${heading} sats:${sats}`);

        // Validar coordenadas
        if (lat < -90 || lat > 90 || lon < -180 || lon > 180) {
          console.warn('[tcp] Coordenadas fuera de rango, descartando');
          lat = null; lon = null;
        }
        // Validar speed/heading
        if (speed > 300)  speed   = null;
        if (heading > 359) heading = null;

      } else if (blockName === 'ign') {
        // Ignición: integer 0x03 o double 0x04
        if (dataType === 0x03 && valBuf.length >= 4) {
          ignition = valBuf.readUInt32BE(0) === 1;
        } else if (dataType === 0x04 && valBuf.length >= 8) {
          ignition = valBuf.readDoubleLE(0) === 1;
        }
      }
    }

    return { unitId, ts, lat, lon, speed, heading, ignition, raw: lat == null ? buf.toString('hex') : null };

  } catch (e) {
    console.error('[tcp] Error parseando paquete:', e.message,
      '— hex:', buf.toString('hex').slice(0, 80));
    return null;
  }
}

function buildAck() {
  return Buffer.from([0x11]);
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
      : 'sin GPS (telemetría)';
    console.log(`[tcp] ✓ ${plate} | ${coords}`);
    return plate;

  } catch (e) {
    console.error('[tcp] Error guardando en BD:', e.message);
    return parsed.unitId;
  }
}

// ── Reenviar a destinos ───────────────────────────────────────────

async function forwardToDestinations(plate, parsed) {
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
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body:    JSON.stringify(payload),
        signal:  AbortSignal.timeout(8000),
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
      console.log(`[tcp] Buffer (${buffer.length}b): ${buffer.toString('hex').slice(0, 200)}`);

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

    socket.on('error', (e) => console.error(`[tcp] Socket error (${remote}):`, e.message));
    socket.on('close', () => console.log(`[tcp] Conexión cerrada: ${remote}`));

    socket.setTimeout(5 * 60 * 1000);
    socket.on('timeout', () => {
      console.warn(`[tcp] Timeout: ${remote}`);
      socket.destroy();
    });
  });

  server.on('error', (e) => console.error('[tcp] Error servidor TCP:', e.message));

  server.listen(TCP_PORT, '0.0.0.0', () => {
    console.log(`✓ TCP Wialon Retranslator escuchando en puerto ${TCP_PORT}`);
  });

  return server;
}

module.exports = { startTcpServer };
