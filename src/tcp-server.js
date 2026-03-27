/**
 * src/tcp-server.js
 * Recibe paquetes Wialon IPS (texto) Y Wialon Retranslator v1.0 (binario) por TCP.
 * Detecta automáticamente el protocolo según el primer byte recibido.
 *
 * Wialon IPS:          primer byte = '#' (0x23)
 * Wialon Retranslator: primer 4 bytes = tamaño del paquete en Little Endian (binario)
 */
'use strict';

const net   = require('net');
const { query } = require('./db/pool');

const TCP_PORT = parseInt(process.env.TCP_PORT || '9001', 10);

// ─── Parser Wialon IPS (texto) ────────────────────────────────────────────────
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
      const [date, time, latRaw, latHem, lonRaw, lonHem, speed, course, alt, sats,, inputs] = body;

      function nmea2dec(raw, hem) {
        const v = parseFloat(raw);
        if (isNaN(v)) return NaN;
        const deg = Math.floor(v / 100);
        const min = v - deg * 100;
        let dec = deg + min / 60;
        if (hem === 'S' || hem === 'W') dec = -dec;
        return dec;
      }

      const lat = nmea2dec(latRaw, latHem);
      const lon = nmea2dec(lonRaw, lonHem);
      if (isNaN(lat) || isNaN(lon)) return null;

      const ignition = inputs && inputs !== 'NA' ? !!(parseInt(inputs, 10) & 1) : false;

      let wialon_ts = null;
      try {
        if (date && time) {
          const dd = date.slice(0,2), mm = date.slice(2,4), yy = date.slice(4,6);
          const hh = time.slice(0,2), mi = time.slice(2,4), ss = time.slice(4,6);
          wialon_ts = new Date(`20${yy}-${mm}-${dd}T${hh}:${mi}:${ss}Z`).toISOString();
        }
      } catch (_) {}

      return {
        type:      'data',
        lat:       parseFloat(lat.toFixed(6)),
        lon:       parseFloat(lon.toFixed(6)),
        speed:     parseFloat(speed  || '0'),
        heading:   parseFloat(course || '0'),
        alt:       parseFloat(alt    || '0'),
        sats:      parseInt(sats     || '0', 10),
        ignition,
        wialon_ts,
        raw:       str,
      };
    }

    if (type === 'P') return { type: 'ping' };
    return null;
  } catch (err) {
    console.error('[TCP] parseWialonIPS error:', err.message);
    return null;
  }
}

// ─── Parser Wialon Retranslator v1.0 (binario) ───────────────────────────────
function parseRetranslatorPacket(buf) {
  try {
    if (buf.length < 8) return null;
    const packetSize = buf.readUInt32LE(0);
    if (buf.length < packetSize + 4) return null;

    let offset = 4;
    const nullIdx = buf.indexOf(0x00, offset);
    if (nullIdx === -1) return null;
    const uid = buf.slice(offset, nullIdx).toString('ascii');
    offset = nullIdx + 1;

    if (offset + 8 > buf.length) return null;
    const timestamp = buf.readUInt32BE(offset); offset += 4;
    offset += 4; // bitmask

    const wialon_ts = timestamp ? new Date(timestamp * 1000).toISOString() : null;
    let lat = null, lon = null, speed = null, heading = null, altitude = null, sats = null;

    while (offset + 6 <= packetSize + 4) {
      if (offset + 6 > buf.length) break;
      const blockType = buf.readUInt16BE(offset); offset += 2;
      const blockSize = buf.readUInt32BE(offset); offset += 4;
      if (blockType !== 0x0BBB) { offset += blockSize; continue; }
      if (offset + blockSize > buf.length) break;
      const blockData = buf.slice(offset, offset + blockSize);
      offset += blockSize;
      if (blockSize < 1) continue;
      let bOff = 0;
      bOff += 1;
      const dataType = blockData[bOff]; bOff += 1;
      const nameNull = blockData.indexOf(0x00, bOff);
      if (nameNull === -1) continue;
      const blockName = blockData.slice(bOff, nameNull).toString('ascii');
      bOff = nameNull + 1;
      if (blockName === 'posinfo' && dataType === 0x02) {
        if (bOff + 27 <= blockData.length) {
          lon      = blockData.readDoubleBE(bOff); bOff += 8;
          lat      = blockData.readDoubleBE(bOff); bOff += 8;
          altitude = blockData.readDoubleBE(bOff); bOff += 8;
          speed    = blockData.readInt16BE(bOff);  bOff += 2;
          heading  = blockData.readInt16BE(bOff);  bOff += 2;
          sats     = blockData[bOff];
        }
      }
    }

    if (lat === null || lon === null) return null;
    return {
      type:       'retranslator_data',
      uid, timestamp, wialon_ts,
      lat:        parseFloat(lat.toFixed(6)),
      lon:        parseFloat(lon.toFixed(6)),
      speed:      speed    ?? 0,
      heading:    heading  ?? 0,
      alt:        altitude ?? 0,
      sats:       sats     ?? 0,
      ignition:   false,
      raw:        buf.slice(0, packetSize + 4).toString('hex').slice(0, 80),
      packetSize: packetSize + 4,
    };
  } catch (err) {
    console.error('[TCP-RT] parseRetranslatorPacket error:', err.message);
    return null;
  }
}

// ─── Buscar unidad ────────────────────────────────────────────────────────────
async function findUnit(imei) {
  const { rows } = await query(
    'SELECT imei, plate, name, rut, enabled, cliente_id FROM public.units WHERE imei = $1',
    [imei]
  );
  return rows[0] || null;
}

// ─── Guardar evento GPS ───────────────────────────────────────────────────────
async function saveEvent(unit, parsed, destinationId, forwardOk, forwardResp) {
  try {
    await query(`
      INSERT INTO public.gps_events
        (plate, imei, lat, lon, speed, heading, ignition, wialon_ts,
         destination_id, forward_ok, forward_resp, raw_hex)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
    `, [
      unit.plate, unit.imei,
      parsed.lat, parsed.lon, parsed.speed, parsed.heading, parsed.ignition,
      parsed.wialon_ts,
      destinationId || null,
      forwardOk     ?? null,
      forwardResp   || null,
      parsed.raw    || null,
    ]);
  } catch (err) {
    console.error('[TCP] saveEvent error:', err.message);
  }
}

// ─── Headers de autenticación ─────────────────────────────────────────────────
function buildAuthHeaders(auth) {
  if (!auth || !auth.type || auth.type === 'none') return {};
  if (auth.type === 'bearer') return { Authorization: `Bearer ${auth.token}` };
  if (auth.type === 'basic') {
    const b64 = Buffer.from(`${auth.username}:${auth.password}`).toString('base64');
    return { Authorization: `Basic ${b64}` };
  }
  if (auth.type === 'apikey') return { [auth.header || 'X-Api-Key']: auth.value };
  return {};
}

// ─── Construir payload dinámico desde field_schema ────────────────────────────
/**
 * Resuelve el valor de cada campo GPS según su "source" configurado en la modal.
 *
 * Las fuentes disponibles coinciden con las opciones en orgs.js GPS_SOURCES:
 *   plate, imei, lat, lon, speed, heading, ignition, ignition01,
 *   wialon_ts, fecha_hora, fecha_slash, alt, sats, hdop, odometro
 */
function resolveSource(source, unit, parsed, clienteData) {
  const pad = n => String(n).padStart(2, '0');
  function toFecha(iso, sep) {
    if (!iso) return '';
    const d = new Date(iso);
    if (isNaN(d)) return iso;
    return `${pad(d.getUTCDate())}${sep}${pad(d.getUTCMonth()+1)}${sep}${d.getUTCFullYear()} `
         + `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
  }

  switch (source) {
    // ── Datos GPS (del dispositivo) ──────────────────────────────────────────
    case 'lat':            return parsed.lat       ?? 0;
    case 'lon':            return parsed.lon       ?? 0;
    case 'speed':          return parsed.speed     ?? 0;
    case 'heading':        return parsed.heading   ?? 0;
    case 'ignition':       return parsed.ignition  ?? false;
    case 'ignition01':     return parsed.ignition  ? 1 : 0;
    case 'wialon_ts':      return parsed.wialon_ts || new Date().toISOString();
    case 'fecha_hora':     return toFecha(parsed.wialon_ts, '-');
    case 'fecha_slash':    return toFecha(parsed.wialon_ts, '/');
    case 'alt':            return parsed.alt       ?? 0;
    case 'sats':           return parsed.sats      ?? 0;
    case 'hdop':           return parsed.hdop      ?? 0;
    case 'odometro':       return parsed.odometro  ?? 0;

    // ── Datos de la unidad (de la DB) ────────────────────────────────────────
    case 'unit_plate':     return unit.plate       || '';
    case 'unit_imei':      return unit.imei        || '';
    case 'unit_name':      return unit.name        || '';
    case 'unit_rut':       return unit.rut         || '';
    case 'cliente_nombre': return clienteData?.nombre || unit.name  || null;
    case 'cliente_rut':    return clienteData?.rut    || unit.rut   || null;

    // ── Retrocompatibilidad con fuentes antiguas ─────────────────────────────
    case 'plate':          return unit.plate || '';
    case 'imei':           return unit.imei  || '';

    default:               return null;
  }
}

/**
 * Construye el payload para un destino a partir de su field_schema.
 *
 * Si el destino tiene campos con "source" configurado → payload mapeado.
 * Si todos los campos tienen source vacío o no hay campos → payload genérico.
 *
 * El resultado siempre es un ARRAY (como requieren la mayoría de APIs GPS).
 * Si el destino necesita un objeto en vez de array, se puede configurar
 * agregando un campo especial con apiKey="__format__" y source="object".
 */
function buildPayload(fieldSchema, unit, parsed, clienteData) {
  const fields = (fieldSchema || [])
    .filter(f => f.apiKey && (f.source || f.source === 'fixed'))
    .sort((a, b) => (a.order || 0) - (b.order || 0));

  // Sin campos mapeados → payload genérico (retrocompatibilidad)
  if (!fields.length) {
    return {
      payload: [{
        imei:     unit.imei,
        plate:    unit.plate,
        lat:      parsed.lat,
        lon:      parsed.lon,
        speed:    parsed.speed,
        heading:  parsed.heading,
        ignition: parsed.ignition,
        ts:       parsed.wialon_ts,
      }],
      missing: [],    // sin campos requeridos faltantes
      warnings: [],
    };
  }

  const obj      = {};
  const missing  = [];   // campos required sin valor
  const warnings = [];   // campos opcionales sin valor

  for (const f of fields) {
    let val;

    if (f.source === 'fixed') {
      val = (f.fixedValue !== undefined && f.fixedValue !== null && f.fixedValue !== '')
        ? f.fixedValue
        : null;
    } else {
      val = resolveSource(f.source, unit, parsed, clienteData);
    }

    // Valor nulo o string vacío → campo sin datos
    const isEmpty = val === null || val === undefined || val === '';

    if (isEmpty) {
      if (f.required) {
        missing.push({ apiKey: f.apiKey, source: f.source, label: f.label });
      } else {
        warnings.push({ apiKey: f.apiKey, source: f.source });
        // Incluir igual con null para que el destino decida qué hacer
        obj[f.apiKey] = null;
      }
    } else {
      obj[f.apiKey] = val;
    }
  }

  return { payload: [obj], missing, warnings };
}

// ─── Reenviar a destinos ──────────────────────────────────────────────────────
async function forwardToDestinations(unit, parsed) {
  // Leer destinos asignados CON su field_schema y auth
  // Cargar datos del cliente de la unidad (para fuentes cliente_nombre, cliente_rut)
  let clienteData = {};
  try {
    if (unit.cliente_id) {
      const { rows: cr } = await query(
        'SELECT nombre, rut FROM public.clientes WHERE id = $1', [unit.cliente_id]
      );
      if (cr[0]) clienteData = cr[0];
    }
  } catch (_) {}

  const { rows: assignments } = await query(`
    SELECT
      ud.shadow,
      d.id          AS dest_id,
      d.name        AS dest_name,
      d.api_url,
      d.field_schema,
      d.auth
    FROM public.unit_destinations ud
    JOIN public.destinations d ON d.id = ud.destination_id
    WHERE ud.imei    = $1
      AND ud.enabled = true
      AND d.enabled  = true
      AND d.api_url IS NOT NULL
      AND d.api_url <> ''
  `, [unit.imei]);

  if (!assignments.length) {
    console.log(`[TCP] ${unit.plate} — sin destinos activos`);
    await saveEvent(unit, parsed, null, null, null);
    return;
  }

  for (const row of assignments) {
    // ── Shadow: registrar sin enviar ─────────────────────────────────────────
    if (row.shadow) {
      console.log(`[TCP] ${unit.plate} → ${row.dest_name} [SHADOW]`);
      await saveEvent(unit, parsed, row.dest_id, null, 'shadow');
      continue;
    }

    // ── Construir payload usando field_schema del destino ────────────────────
    let fieldSchema = [];
    try {
      fieldSchema = typeof row.field_schema === 'string'
        ? JSON.parse(row.field_schema)
        : (row.field_schema || []);
    } catch (_) {}

    const { payload: payloadArray, missing, warnings } = buildPayload(fieldSchema, unit, parsed, clienteData);

    // ── Campos requeridos faltantes → no enviar ───────────────────────────────
    if (missing.length > 0) {
      const faltantes = missing.map(f => `${f.apiKey}(${f.source})`).join(', ');
      const errMsg    = `CAMPOS_FALTANTES: ${faltantes}`;
      console.error(`[TCP] ${unit.plate} → ${row.dest_name} ✗ ${errMsg}`);
      await saveEvent(unit, parsed, row.dest_id, false, errMsg);
      continue;
    }

    // ── Advertencias de campos opcionales vacíos ─────────────────────────────
    if (warnings.length > 0) {
      const warnFields = warnings.map(f => f.apiKey).join(', ');
      console.warn(`[TCP] ${unit.plate} → ${row.dest_name} ⚠ campos opcionales vacíos: ${warnFields}`);
    }

    // ── Auth headers ─────────────────────────────────────────────────────────
    let auth = null;
    try {
      auth = typeof row.auth === 'string' ? JSON.parse(row.auth) : row.auth;
    } catch (_) {}
    const authHeaders = buildAuthHeaders(auth);
    // LOG DIAGNÓSTICO — remover cuando se resuelva el 401
    console.log(`[AUTH-DEBUG] ${row.dest_name} | type=${auth?.type} | token_len=${auth?.token?.length} | headers=${JSON.stringify(authHeaders).slice(0,80)}`);

    // Loguear modo
    const mappedFields = fieldSchema.filter(f => f.source).length;
    const mode = mappedFields > 0 ? `mapeo(${mappedFields} campos)` : 'genérico';
    console.log(`[TCP] ${unit.plate} → ${row.dest_name} [${mode}]`);

    // ── Enviar ───────────────────────────────────────────────────────────────
    let forwardOk = false, forwardResp = null;
    try {
      const res = await fetch(row.api_url, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json', ...authHeaders },
        body:    JSON.stringify(payloadArray),
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
    const remoteAddr = socket.remoteAddress || '?';
    let sessionImei = null;
    let protocol    = null; // 'ips' | 'retranslator' | null
    let ipsBuffer   = '';
    let rtBuffer    = Buffer.alloc(0);

    console.log(`[TCP] Nueva conexión desde ${remoteAddr}`);

    const noDataTimer = setTimeout(() => {
      console.warn(`[TCP] Sin datos en 20s desde ${remoteAddr} — cerrando`);
      socket.destroy();
    }, 20000);

    socket.on('data', async (chunk) => {
      clearTimeout(noDataTimer);

      // Detectar protocolo por el primer byte
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

      // ── Wialon IPS ─────────────────────────────────────────────────────────
      if (protocol === 'ips') {
        ipsBuffer += chunk.toString('ascii');
        const lines = ipsBuffer.split('\r\n');
        ipsBuffer   = lines.pop();

        for (const line of lines) {
          if (!line.trim()) continue;
          console.log(`[TCP-IPS] RAW: ${line.slice(0, 100)}`);
          const parsed = parseWialonIPS(line);
          if (!parsed) { console.warn(`[TCP-IPS] Línea no reconocida: ${line.slice(0, 80)}`); continue; }

          if (parsed.type === 'login') {
            sessionImei = parsed.imei;
            socket.write('#AL#1\r\n');
            console.log(`[TCP-IPS] Login IMEI: ${sessionImei}`);
            continue;
          }
          if (parsed.type === 'ping') { socket.write('#AP#\r\n'); continue; }
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

      // ── Wialon Retranslator ─────────────────────────────────────────────────
      if (protocol === 'retranslator') {
        rtBuffer = Buffer.concat([rtBuffer, chunk]);

        while (rtBuffer.length >= 4) {
          const packetSize = rtBuffer.readUInt32LE(0);
          if (rtBuffer.length < packetSize + 4) break;

          const packetBuf = rtBuffer.slice(0, packetSize + 4);
          rtBuffer        = rtBuffer.slice(packetSize + 4);

          console.log(`[TCP-RT] Paquete recibido: ${packetSize + 4} bytes desde ${remoteAddr}`);
          const parsed = parseRetranslatorPacket(packetBuf);

          if (!parsed) {
            console.warn(`[TCP-RT] Paquete no parseable desde ${remoteAddr}`);
            socket.write(Buffer.from([0x11]));
            continue;
          }

          console.log(`[TCP-RT] UID: ${parsed.uid} | lat: ${parsed.lat} lon: ${parsed.lon} speed: ${parsed.speed}`);
          socket.write(Buffer.from([0x11]));

          const unit = await findUnit(parsed.uid);
          if (!unit)         { console.warn(`[TCP-RT] UID/IMEI ${parsed.uid} no registrado`); continue; }
          if (!unit.enabled) { console.log(`[TCP-RT] ${unit.plate} deshabilitada`); continue; }

          sessionImei = parsed.uid;
          await forwardToDestinations(unit, {
            lat:       parsed.lat,
            lon:       parsed.lon,
            speed:     parsed.speed,
            heading:   parsed.heading,
            alt:       parsed.alt,
            sats:      parsed.sats,
            ignition:  parsed.ignition,
            wialon_ts: parsed.wialon_ts,
            raw:       parsed.raw,
          });
        }
      }
    });

    socket.on('error', (err) => {
      clearTimeout(noDataTimer);
      console.error(`[TCP] Socket error desde ${remoteAddr}:`, err.message);
    });

    socket.on('close', () => {
      clearTimeout(noDataTimer);
      console.log(`[TCP] Conexión cerrada${sessionImei ? ' IMEI:' + sessionImei : ''} (${remoteAddr}) protocolo:${protocol || 'desconocido'}`);
    });
  });

  server.listen(TCP_PORT, '0.0.0.0', () => {
    console.log(`[TCP] Servidor escuchando en puerto ${TCP_PORT} (IPS + Retranslator v1.0)`);
  });

  server.on('error', (err) => console.error('[TCP] Server error:', err.message));
  return server;
}

module.exports = { startTcpServer };
