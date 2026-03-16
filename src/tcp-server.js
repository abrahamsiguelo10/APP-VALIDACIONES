/**
 * src/tcp-server.js
 * Recibe paquetes Wialon IPS (texto) Y Wialon Retranslator v1.0 (binario) por TCP.
 * Detecta automáticamente el protocolo según el primer byte recibido.
 *
 * Wialon IPS:          primer byte = '#' (0x23)
 * Wialon Retranslator: primer 4 bytes = tamaño del paquete en Little Endian (binario)
 */

'use strict';

const net       = require('net');
const { query } = require('./db/pool');

const TCP_PORT = parseInt(process.env.TCP_PORT || '9001', 10);

// ─── Parser Wialon IPS (texto) ────────────────────────────────────────────────
// Formato: #D#date;time;lat1;lat2;lon1;lon2;speed;course;alt;sats;hdop;inputs;...
function parseWialonIPS(raw) {
  try {
    const str = raw.toString('ascii').trim();
    if (!str.startsWith('#')) return null;

    const parts = str.split('#').filter(Boolean);
    const type  = parts[0];

    if (type === 'L') {
      const body = (parts[1] || '').split(';');
      return { type: 'login', imei: body[0]?.trim(), pass: body[1]?.trim() };
    }

    if (type === 'D' || type === 'SD') {
      const body = (parts[1] || '').split(';');
      const [date, time, lat1, lat2, lon1, lon2, speed, course,,, inputs] = body;

      const lat = parseFloat(lat1) + parseFloat(lat2) / 60;
      const lon = parseFloat(lon1) + parseFloat(lon2) / 60;
      if (isNaN(lat) || isNaN(lon)) return null;

      const ignition = !!(parseInt(inputs || '0', 10) & 1);

      let wialon_ts = null;
      try {
        if (date && time) {
          const [d, m, y] = date.split('.');
          const [h, mi, s] = time.split(':');
          wialon_ts = new Date(`20${y}-${m}-${d}T${h}:${mi}:${s}Z`).toISOString();
        }
      } catch (_) {}

      return {
        type:    'data',
        lat:     parseFloat(lat.toFixed(6)),
        lon:     parseFloat(lon.toFixed(6)),
        speed:   parseFloat(speed || '0'),
        heading: parseFloat(course || '0'),
        ignition,
        wialon_ts,
        raw:     str,
      };
    }
    return null;
  } catch (err) {
    console.error('[TCP] parseWialonIPS error:', err.message);
    return null;
  }
}

// ─── Parser Wialon Retranslator v1.0 (binario) ────────────────────────────────
// Estructura del paquete:
//   [4B LE]  Packet size (sin incluir estos 4 bytes)
//   [N+1B]   UID string terminado en 0x00
//   [4B]     Unix timestamp (Big Endian)
//   [4B]     Bitmask (qué bloques siguen)
//   [bloques] Cada bloque: [2B type 0x0BBB][4B size BE][size bytes de data]
//
// Bloque posinfo (type 0x0002 dentro del bloque):
//   [8B double LE] Longitude
//   [8B double LE] Latitude
//   [8B double LE] Altitude
//   [2B short  BE] Speed (km/h)
//   [2B short  BE] Course (0-359)
//   [1B byte]      Satellites
//
// Respuesta del servidor: 0x11 por cada paquete válido

function parseRetranslatorPacket(buf) {
  try {
    if (buf.length < 8) return null;

    // Tamaño del paquete (sin los 4 bytes del size)
    const packetSize = buf.readUInt32LE(0);
    if (buf.length < packetSize + 4) return null; // paquete incompleto

    let offset = 4;

    // UID: string terminado en 0x00
    const nullIdx = buf.indexOf(0x00, offset);
    if (nullIdx === -1) return null;
    const uid = buf.slice(offset, nullIdx).toString('ascii');
    offset = nullIdx + 1;

    if (offset + 8 > buf.length) return null;

    // Timestamp (4 bytes Big Endian)
    const timestamp = buf.readUInt32BE(offset);
    offset += 4;

    // Bitmask (4 bytes) — indica qué bloques vienen
    const bitmask = buf.readUInt32BE(offset);
    offset += 4;

    const wialon_ts = timestamp ? new Date(timestamp * 1000).toISOString() : null;

    // Parsear bloques de datos
    let lat = null, lon = null, speed = null, heading = null, altitude = null, sats = null;

    while (offset + 6 <= packetSize + 4) {
      // Cada bloque: 2 bytes tipo (siempre 0x0BBB) + 4 bytes tamaño
      if (offset + 6 > buf.length) break;

      const blockType = buf.readUInt16BE(offset);
      offset += 2;
      const blockSize = buf.readUInt32BE(offset);
      offset += 4;

      if (blockType !== 0x0BBB) {
        offset += blockSize;
        continue;
      }

      if (offset + blockSize > buf.length) break;
      const blockData = buf.slice(offset, offset + blockSize);
      offset += blockSize;

      if (blockSize < 1) continue;

      // Security attribute (1 byte) + data type (1 byte) + nombre (hasta 0x00) + valor
      let bOff = 0;
      bOff += 1; // security attribute — skip

      if (bOff >= blockData.length) continue;
      const dataType = blockData[bOff];
      bOff += 1;

      // Nombre del bloque (string hasta 0x00)
      const nameNull = blockData.indexOf(0x00, bOff);
      if (nameNull === -1) continue;
      const blockName = blockData.slice(bOff, nameNull).toString('ascii');
      bOff = nameNull + 1;

      if (blockName === 'posinfo' && dataType === 0x02) {
        // posinfo: lon(8) lat(8) alt(8) speed(2) course(2) sats(1)
        if (bOff + 27 <= blockData.length) {
          lon      = blockData.readDoubleBE(bOff);     bOff += 8;
          lat      = blockData.readDoubleBE(bOff);     bOff += 8;
          altitude = blockData.readDoubleBE(bOff);     bOff += 8;
          speed    = blockData.readInt16BE(bOff);      bOff += 2;
          heading  = blockData.readInt16BE(bOff);      bOff += 2;
          sats     = blockData[bOff];
        }
      }
    }

    if (lat === null || lon === null) return null;

    return {
      type:       'retranslator_data',
      uid,
      timestamp,
      wialon_ts,
      lat:        parseFloat(lat.toFixed(6)),
      lon:        parseFloat(lon.toFixed(6)),
      speed:      speed ?? 0,
      heading:    heading ?? 0,
      altitude:   altitude ?? 0,
      sats:       sats ?? 0,
      ignition:   false, // no incluido en posinfo básico
      raw:        buf.slice(0, packetSize + 4).toString('hex').slice(0, 80),
      packetSize: packetSize + 4,
    };
  } catch (err) {
    console.error('[TCP-RT] parseRetranslatorPacket error:', err.message);
    return null;
  }
}

// ─── Buscar unidad por IMEI o UID ─────────────────────────────────────────────
async function findUnit(imei) {
  const { rows } = await query(
    'SELECT imei, plate, name, enabled FROM public.units WHERE imei = $1',
    [imei]
  );
  return rows[0] || null;
}

// ─── Guardar evento GPS ───────────────────────────────────────────────────────
async function saveEvent(unit, parsed, destinationId, forwardOk, forwardResp) {
  try {
    await query(`
      INSERT INTO public.gps_events
        (plate, imei, lat, lon, speed, heading, ignition,
         wialon_ts, destination_id, forward_ok, forward_resp, raw_hex)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
    `, [
      unit.plate, unit.imei,
      parsed.lat, parsed.lon, parsed.speed, parsed.heading, parsed.ignition,
      parsed.wialon_ts,
      destinationId  || null,
      forwardOk      ?? null,
      forwardResp    || null,
      parsed.raw     || null,
    ]);
  } catch (err) {
    console.error('[TCP] saveEvent error:', err.message);
  }
}

// ─── Headers de autenticación ─────────────────────────────────────────────────
function buildAuthHeaders(auth) {
  if (!auth || !auth.type || auth.type === 'none') return {};
  if (auth.type === 'bearer')  return { Authorization: `Bearer ${auth.token}` };
  if (auth.type === 'basic') {
    const b64 = Buffer.from(`${auth.username}:${auth.password}`).toString('base64');
    return { Authorization: `Basic ${b64}` };
  }
  if (auth.type === 'apikey')  return { [auth.header || 'X-Api-Key']: auth.value };
  return {};
}

// ─── Reenviar a destinos ──────────────────────────────────────────────────────
async function forwardToDestinations(unit, parsed) {
  const { rows: assignments } = await query(`
    SELECT ud.shadow, d.id AS dest_id, d.name AS dest_name, d.api_url
    FROM  public.unit_destinations ud
    JOIN  public.destinations d ON d.id = ud.destination_id
    WHERE ud.imei    = $1
      AND ud.enabled = true
      AND d.enabled  = true
      AND d.api_url  IS NOT NULL
      AND d.api_url  <> ''
  `, [unit.imei]);

  if (!assignments.length) {
    console.log(`[TCP] ${unit.plate} — sin destinos activos`);
    await saveEvent(unit, parsed, null, null, null);
    return;
  }

  for (const row of assignments) {
    if (row.shadow) {
      console.log(`[TCP] ${unit.plate} → ${row.dest_name} [SHADOW]`);
      await saveEvent(unit, parsed, row.dest_id, null, 'shadow');
      continue;
    }

    // Leer auth por separado — graceful si columna no existe
    let authHeaders = {};
    try {
      const { rows: dr } = await query(
        'SELECT auth FROM public.destinations WHERE id = $1', [row.dest_id]
      );
      if (dr[0]?.auth) authHeaders = buildAuthHeaders(dr[0].auth);
    } catch (_) {}

    const payload = {
      imei:     unit.imei,
      plate:    unit.plate,
      lat:      parsed.lat,
      lon:      parsed.lon,
      speed:    parsed.speed,
      heading:  parsed.heading,
      ignition: parsed.ignition,
      ts:       parsed.wialon_ts,
    };

    let forwardOk = false, forwardResp = null;
    try {
      const res = await fetch(row.api_url, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json', ...authHeaders },
        body:    JSON.stringify(payload),
        signal:  AbortSignal.timeout(8000),
      });
      forwardOk   = res.ok;
      forwardResp = `${res.status} ${res.statusText}`.slice(0, 500);
      console.log(`[TCP] ${unit.plate} → ${row.dest_name} ${forwardOk ? '✓' : '✗'} (${res.status})`);
    } catch (err) {
      forwardResp = err.message?.slice(0, 500) || 'error';
      console.error(`[TCP] ${unit.plate} → ${row.dest_name} error:`, err.message);
    }

    await saveEvent(unit, parsed, row.dest_id, forwardOk, forwardResp);
  }
}

// ─── Servidor TCP ─────────────────────────────────────────────────────────────
function startTcpServer() {
  if (process.env.TCP_ENABLED !== 'true') {
    console.log('[TCP] TCP_ENABLED != true — servidor no iniciado');
    return;
  }

  const server = net.createServer((socket) => {
    const remoteAddr  = socket.remoteAddress || '?';
    let sessionImei   = null;
    let protocol      = null; // 'ips' | 'retranslator' | null
    let ipsBuffer     = '';
    let rtBuffer      = Buffer.alloc(0);

    console.log(`[TCP] Nueva conexión desde ${remoteAddr}`);

    // Timeout: si en 20s no llega ningún byte, cerrar
    const noDataTimer = setTimeout(() => {
      console.warn(`[TCP] Sin datos en 20s desde ${remoteAddr} — cerrando`);
      socket.destroy();
    }, 20000);

    socket.on('data', async (chunk) => {
      clearTimeout(noDataTimer);

      // Detectar protocolo por el primer byte recibido
      if (protocol === null) {
        const firstByte = chunk[0];
        if (firstByte === 0x23) { // '#'
          protocol = 'ips';
          console.log(`[TCP] Protocolo: Wialon IPS (texto) desde ${remoteAddr}`);
        } else {
          protocol = 'retranslator';
          console.log(`[TCP] Protocolo: Wialon Retranslator (binario) desde ${remoteAddr}`);
        }
      }

      // ── Protocolo Wialon IPS ──────────────────────────────────────────────
      if (protocol === 'ips') {
        ipsBuffer += chunk.toString('ascii');
        const lines = ipsBuffer.split('\r\n');
        ipsBuffer = lines.pop();

        for (const line of lines) {
          if (!line.trim()) continue;
          console.log(`[TCP-IPS] RAW: ${line.slice(0, 100)}`);
          const parsed = parseWialonIPS(line);
          if (!parsed) {
            console.warn(`[TCP-IPS] Línea no reconocida: ${line.slice(0, 80)}`);
            continue;
          }

          if (parsed.type === 'login') {
            sessionImei = parsed.imei;
            socket.write('#AL#1\r\n');
            console.log(`[TCP-IPS] Login IMEI: ${sessionImei}`);
            continue;
          }

          if (parsed.type === 'data') {
            socket.write('#AD#1\r\n');
            if (!sessionImei) { console.warn('[TCP-IPS] Datos sin login'); continue; }
            const unit = await findUnit(sessionImei);
            if (!unit)         { console.warn(`[TCP-IPS] IMEI ${sessionImei} no registrado`); continue; }
            if (!unit.enabled) { console.log(`[TCP-IPS] ${unit.plate} deshabilitada`); continue; }
            await forwardToDestinations(unit, parsed);
          }
        }
      }

      // ── Protocolo Wialon Retranslator ─────────────────────────────────────
      if (protocol === 'retranslator') {
        rtBuffer = Buffer.concat([rtBuffer, chunk]);

        // Procesar todos los paquetes completos en el buffer
        while (rtBuffer.length >= 4) {
          const packetSize = rtBuffer.readUInt32LE(0);

          // Esperar hasta tener el paquete completo
          if (rtBuffer.length < packetSize + 4) break;

          const packetBuf = rtBuffer.slice(0, packetSize + 4);
          rtBuffer = rtBuffer.slice(packetSize + 4); // consumir del buffer

          console.log(`[TCP-RT] Paquete recibido: ${packetSize + 4} bytes desde ${remoteAddr}`);

          const parsed = parseRetranslatorPacket(packetBuf);

          if (!parsed) {
            console.warn(`[TCP-RT] Paquete no parseable desde ${remoteAddr}: ${packetBuf.slice(0,20).toString('hex')}`);
            // Responder 0x11 igual para no bloquear al retransmisor
            socket.write(Buffer.from([0x11]));
            continue;
          }

          console.log(`[TCP-RT] UID: ${parsed.uid} | lat: ${parsed.lat} lon: ${parsed.lon} speed: ${parsed.speed}`);

          // Responder 0x11 inmediatamente (ACK del protocolo Retranslator)
          socket.write(Buffer.from([0x11]));

          // Buscar la unidad por el UID del retransmisor
          // El UID en Wialon Retranslator es el IMEI del dispositivo
          const unit = await findUnit(parsed.uid);
          if (!unit) {
            console.warn(`[TCP-RT] UID/IMEI ${parsed.uid} no registrado en la DB`);
            continue;
          }
          if (!unit.enabled) {
            console.log(`[TCP-RT] ${unit.plate} deshabilitada`);
            continue;
          }

          sessionImei = parsed.uid;

          // Normalizar el parsed para reutilizar forwardToDestinations
          const normalizedParsed = {
            lat:       parsed.lat,
            lon:       parsed.lon,
            speed:     parsed.speed,
            heading:   parsed.heading,
            ignition:  parsed.ignition,
            wialon_ts: parsed.wialon_ts,
            raw:       parsed.raw,
          };

          await forwardToDestinations(unit, normalizedParsed);
        }
      }
    });

    socket.on('error', (err) => {
      clearTimeout(noDataTimer);
      console.error(`[TCP] Socket error desde ${remoteAddr}:`, err.message);
    });

    socket.on('close', () => {
      clearTimeout(noDataTimer);
      console.log(`[TCP] Conexión cerrada${sessionImei ? ' UID/IMEI:' + sessionImei : ''} (${remoteAddr}) protocolo:${protocol || 'desconocido'}`);
    });
  });

  server.listen(TCP_PORT, '0.0.0.0', () => {
    console.log(`[TCP] Servidor escuchando en puerto ${TCP_PORT} (IPS + Retranslator v1.0)`);
  });

  server.on('error', (err) => console.error('[TCP] Server error:', err.message));
  return server;
}

module.exports = { startTcpServer };
