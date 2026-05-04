'use strict';

/**
 * src/tcp-server.js
 * Recibe paquetes Wialon IPS (texto) Y Wialon Retranslator v1.0 (binario) por TCP.
 * Detecta automáticamente el protocolo según el primer byte recibido.
 *
 * Wialon IPS:          primer byte = '#' (0x23)
 * Wialon Retranslator: primer 4 bytes = tamaño del paquete en Little Endian (binario)
 */

// ── Handlers globales de error — evitan que el proceso muera por errores no capturados ──
process.on('uncaughtException', (err) => {
  console.error('[TCP] uncaughtException:', err.message, err.stack?.split('\n')[1] || '');
});

process.on('unhandledRejection', (reason) => {
  console.error('[TCP] unhandledRejection:', reason?.message || reason);
});

const net   = require('net');
const { query } = require('./db/pool');

const TCP_PORT = parseInt(process.env.TCP_PORT || '9001', 10);

// ─── Caché en memoria ─────────────────────────────────────────────────────────
// Evita queries repetidas a Supabase por datos que casi nunca cambian.
// Con 200 unidades × 1 evento/s = 600 queries/s sin caché → ~3 queries/s con caché.

const CACHE_TTL_MS       = 60_000;   // 60 segundos TTL general
const CACHE_DEST_TTL_MS  = 120_000;  // 2 minutos para destinos (cambian menos)
const CACHE_GEO_TTL_MS   = 30 * 60_000; // ← NUEVO: 30 min para direcciones

const _unitCache    = new Map(); // imei       → { data, expiresAt }
const _destCache    = new Map(); // imei       → { data, expiresAt }
const _clienteCache = new Map(); // cliente_id → { data, expiresAt }
const _geocodeCache = new Map(); // "lat,lon"  → { data, expiresAt } ← NUEVO

function cacheGet(map, key) {
  const entry = map.get(key);
  if (!entry) return undefined;
  if (Date.now() > entry.expiresAt) { map.delete(key); return undefined; }
  return entry.data;
}

function cacheSet(map, key, data, ttl = CACHE_TTL_MS) {
  map.set(key, { data, expiresAt: Date.now() + ttl });
}

// Limpiar caché expirado cada 5 minutos para evitar memory leaks
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of _unitCache)    { if (now > v.expiresAt) _unitCache.delete(k); }
  for (const [k, v] of _destCache)    { if (now > v.expiresAt) _destCache.delete(k); }
  for (const [k, v] of _clienteCache) { if (now > v.expiresAt) _clienteCache.delete(k); }
  for (const [k, v] of _geocodeCache) { if (now > v.expiresAt) _geocodeCache.delete(k); } // ← NUEVO
}, 5 * 60_000);

// ─── NUEVO: Reverse Geocoding — Nominatim (OpenStreetMap) ────────────────────
// Gratuito, sin API key. Política: max 1 req/s con User-Agent identificado.
// Con caché de 30 min y ~200 unidades el uso es < 1 req/min. Completamente seguro.
// Devuelve string con la dirección formateada o null si falla.
async function getReverseGeocode(lat, lon) {
  if (!lat || !lon || (lat === 0 && lon === 0)) return null;

  // Redondear a 4 decimales (~11m) para maximizar hits de caché entre eventos cercanos
  const key = `${Number(lat).toFixed(4)},${Number(lon).toFixed(4)}`;

  const cached = cacheGet(_geocodeCache, key);
  if (cached !== undefined) return cached; // null también se cachea (evita re-intentos)

  try {
    const url = `https://nominatim.openstreetmap.org/reverse?lat=${lat}&lon=${lon}&format=json&addressdetails=1`;
    const res = await fetch(url, {
      headers: { 'User-Agent': 'SigueloGPS/1.0 (siguelo.cl)' },
      signal:  AbortSignal.timeout(5000),
    });

    if (!res.ok) {
      cacheSet(_geocodeCache, key, null, CACHE_GEO_TTL_MS);
      return null;
    }

    const data = await res.json();
    let address = null;

    if (data?.address) {
      const a = data.address;
      // Construir: "Calle Número, Ciudad, Región, País"
      const parts = [
        a.road || a.pedestrian || a.path || a.footway || a.highway || '',
        a.house_number || '',
        a.city || a.town || a.village || a.municipality || a.county || '',
        a.state || a.region || '',
        a.country || '',
      ].filter(Boolean);
      address = parts.join(', ') || data.display_name?.slice(0, 250) || null;
    } else if (data?.display_name) {
      address = data.display_name.slice(0, 250);
    }

    cacheSet(_geocodeCache, key, address, CACHE_GEO_TTL_MS);
    if (address) console.log(`[GEO] ${lat},${lon} → ${address.slice(0, 80)}`);
    return address;

  } catch (err) {
    console.warn(`[GEO] reverse geocode failed lat=${lat} lon=${lon}: ${err.message}`);
    cacheSet(_geocodeCache, key, null, CACHE_GEO_TTL_MS);
    return null;
  }
}

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
      const [date, time, latRaw, latHem, lonRaw, lonHem, speed, course, alt, sats,, inputs, outputs, adc, ibutton, params] = body;
  
      const parsedParams = {};
      if (params && params !== 'NA' && params !== '') {
        for (const p of params.split(',')) {
          const [name, type, value] = p.split(':');
          if (name && value !== undefined) {
            parsedParams[name.toLowerCase()] = type === '2' ? parseInt(value, 10)
              : type === '1' ? parseFloat(value)
              : value;
          }
        }
      }
      const odometro = parsedParams['odometer'] ?? parsedParams['odo'] ?? parsedParams['mileage'] ?? null;
      const hdopVal  = parsedParams['hdop'] ?? null;
      // Horometro: horas de motor encendido acumuladas
      const hourmeter = parsedParams['engine_hours'] ?? parsedParams['engine_hours_adj'] ?? 
                        parsedParams['hourmeter']    ?? parsedParams['total_time']       ?? null;

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

      const inputsVal          = inputs && inputs !== 'NA' ? parseInt(inputs, 10) : 0;
      const ignitionFromInputs = !!(inputsVal & 1);
      // Fallback: si inputs no reporta ignición pero hay velocidad > 0, inferir encendido
      const speedVal  = parseFloat(speed) || 0;
      const ignition  = ignitionFromInputs || speedVal > 0;

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
        odometro,
        hdop: hdopVal,
        hourmeter,
        wialon_ts,
        raw: str,
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
    let ignition = null;

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
      bOff += 1; // stealth attribute
      const dataType = blockData[bOff]; bOff += 1;
      const nameNull = blockData.indexOf(0x00, bOff);
      if (nameNull === -1) continue;
      const blockName = blockData.slice(bOff, nameNull).toString('ascii');
      bOff = nameNull + 1;

      if (blockName === 'posinfo' && dataType === 0x02) {
        if (bOff + 27 <= blockData.length) {
          lon      = blockData.readDoubleLE(bOff); bOff += 8;
          lat      = blockData.readDoubleLE(bOff); bOff += 8;
          altitude = blockData.readDoubleLE(bOff); bOff += 8;
          speed    = blockData.readInt16BE(bOff);  bOff += 2;
          heading  = blockData.readInt16BE(bOff);  bOff += 2;
          sats     = blockData[bOff]; bOff += 1;
        } else { break; }
      } else if (blockName === 'avl_inputs' && dataType === 0x03) {
        if (bOff + 4 <= blockData.length) {
          const inputs = blockData.readUInt32BE(bOff);
          ignition = (inputs & 0x01) === 1;
        }
      } else if ((blockName === 'ign' || blockName === 'engine operation') && dataType === 0x04) {
        if (bOff + 8 <= blockData.length) {
          const val = blockData.readDoubleLE(bOff);
          ignition = val >= 1.0;
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
      ignition:   ignition !== null ? ignition : (speed !== null && speed > 0),
      raw:        buf.slice(0, packetSize + 4).toString('hex'),
      packetSize: packetSize + 4,
    };
  } catch (err) {
    console.error('[TCP-RT] parseRetranslatorPacket error:', err.message);
    return null;
  }
}

// ─── Buscar unidad ────────────────────────────────────────────────────────────
async function findUnit(imei) {
  const cached = cacheGet(_unitCache, imei);
  if (cached !== undefined) return cached;
  const { rows } = await query(
    'SELECT imei, plate, name, rut, enabled, cliente_id FROM public.units WHERE imei = $1',
    [imei]
  );
  const unit = rows[0] || null;
  cacheSet(_unitCache, imei, unit, CACHE_TTL_MS);
  return unit;
}

// ─── Guardar evento GPS ───────────────────────────────────────────────────────
async function saveEvent(unit, parsed, destinationId, forwardOk, forwardResp, payloadSent) {
  try {
    await query(`
      INSERT INTO public.gps_events
        (plate, imei, lat, lon, speed, heading, ignition, wialon_ts,
         destination_id, forward_ok, forward_resp, raw_hex, payload_sent)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
    `, [
      unit.plate, unit.imei,
      parsed.lat, parsed.lon, parsed.speed, parsed.heading, parsed.ignition,
      parsed.wialon_ts,
      destinationId || null,
      forwardOk     ?? null,
      forwardResp   || null,
      parsed.raw    || null,
      payloadSent   ? JSON.stringify(payloadSent) : null,
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
  if (auth.type === 'bearer+basic') return { Authorization: `Bearer ${auth.token}` };
  if (auth.type === 'apikey') return { [auth.header || 'X-Api-Key']: auth.value };
  if (auth.type === 'custom-headers' && !Array.isArray(auth.headers)) {
    const headers = {};
    if (auth.username_header && auth.username) headers[auth.username_header] = auth.username;
    if (auth.password_header && auth.password) headers[auth.password_header] = auth.password;
    if (auth.token_header    && auth.token)    headers[auth.token_header]    = auth.token;
    return headers;
  }
  if (auth.type === 'custom-headers' && Array.isArray(auth.headers)) {
    const headers = {};
    for (const h of auth.headers) {
      if (h.key && h.value !== undefined && h.value !== '') headers[h.key] = h.value;
    }
    return headers;
  }
  return {};
}

function injectAuthInBody(auth, payloadArray) {
  if (!auth) return payloadArray;
  const inject = {};
  if (auth.type === 'basic-in-body') {
    if (auth.username) inject.username = auth.username;
    if (auth.password) inject.password = auth.password;
  }
  if (auth.type === 'bearer+basic') {
    if (auth.username) inject.username = auth.username;
    if (auth.password) inject.password = auth.password;
  }
  if (!Object.keys(inject).length) return payloadArray;
  return payloadArray.map(item => ({ ...inject, ...item }));
}

// ── Cargador de drivers externos ─────────────────────────────────────────────
const _driverCache = {};
function loadDriver(slug) {
  if (_driverCache[slug]) return _driverCache[slug];
  const candidates = [
    require.resolve ? (() => { try { return require('./drivers/' + slug); } catch(_) { return null; } })() : null,
  ];
  const driver = candidates.find(Boolean);
  if (!driver) { console.warn(`[TCP] Driver "${slug}" no encontrado en ./drivers/`); return null; }
  _driverCache[slug] = driver;
  console.log(`[TCP] Driver "${slug}" cargado`);
  return driver;
}

// ─── resolveSource ────────────────────────────────────────────────────────────
// NOTA: puede devolver una Promise para el case 'address'.
// buildPayload() lo awaita automáticamente.
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
    case 'lat':        return parsed.lat      ?? 0;
    case 'lon':        return parsed.lon      ?? 0;
    case 'speed':      return parsed.speed    ?? 0;
    case 'heading':    return parsed.heading  ?? 0;
    case 'ignition':   return parsed.ignition ?? false;
    case 'ignition01': return parsed.ignition ? 1 : 0;
    case 'skynav_evento': {
      const ign    = parsed.ignition === true || parsed.ignition === 1;
      const moving = Number(parsed.speed || 0) > 0;
      if (moving) return ign ? 41 : 52;
      return ign ? 51 : 42;
    }
    case 'wialon_ts':   return parsed.wialon_ts || new Date().toISOString();
    case 'fecha_hora':  return toFecha(parsed.wialon_ts, '-');
    case 'fecha_slash': return toFecha(parsed.wialon_ts, '/');
    case 'fecha_chile': {
      const iso = parsed.wialon_ts || new Date().toISOString();
      try {
        const d = new Date(new Date(iso).toLocaleString('en-US', { timeZone: 'America/Santiago' }));
        const p = n => String(n).padStart(2, '0');
        return `${p(d.getDate())}-${p(d.getMonth()+1)}-${d.getFullYear()} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
      } catch (_) { return iso; }
    }
    case 'fecha_chile_iso': {
      const iso = parsed.wialon_ts || new Date().toISOString();
      try {
        const d = new Date(new Date(iso).toLocaleString('en-US', { timeZone: 'America/Santiago' }));
        const p = n => String(n).padStart(2, '0');
        return `${d.getFullYear()}-${p(d.getMonth()+1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
      } catch (_) { return iso; }
    }
    case 'fecha_utc_off': {
      const iso = parsed.wialon_ts || new Date().toISOString();
      const d   = new Date(iso);
      if (isNaN(d)) return iso;
      const p = n => String(n).padStart(2, '0');
      return `${d.getUTCFullYear()}-${p(d.getUTCMonth()+1)}-${p(d.getUTCDate())} ` +
             `${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())} +00:00`;
    }
    case 'fecha_utc': {
      // Formato UTC puro: "YYYY-MM-DD HH:MM:SS" (sin zona horaria) — requerido por Sitrack
      const iso = parsed.wialon_ts || new Date().toISOString();
      const d   = new Date(iso);
      if (isNaN(d)) return iso;
      const p = n => String(n).padStart(2, '0');
      return `${d.getUTCFullYear()}-${p(d.getUTCMonth()+1)}-${p(d.getUTCDate())} ` +
             `${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())}`;
    }
    case 'fecha_gmt': {
      const iso = parsed.wialon_ts || new Date().toISOString();
      const d   = new Date(iso);
      if (isNaN(d)) return iso;
      const p = n => String(n).padStart(2, '0');
      return `${d.getUTCFullYear()}-${p(d.getUTCMonth()+1)}-${p(d.getUTCDate())} ` +
             `${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())} GMT`;
    }
    case 'wialon_ts_offset': {
      const iso = parsed.wialon_ts || new Date().toISOString();
      try {
        const d   = new Date(new Date(iso).toLocaleString('en-US', { timeZone: 'America/Santiago' }));
        const utc = new Date(iso);
        const off = Math.round((d - utc) / 3600000);
        const sign   = off >= 0 ? '+' : '-';
        const absOff = String(Math.abs(off)).padStart(2, '0');
        const p = n => String(n).padStart(2, '0');
        return `${d.getFullYear()}-${p(d.getMonth()+1)}-${p(d.getDate())}` +
               `T${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}${sign}${absOff}00`;
      } catch (_) {
        const d = new Date(new Date(iso).getTime() - 4 * 3600 * 1000);
        const p = n => String(n).padStart(2, '0');
        return `${d.getUTCFullYear()}-${p(d.getUTCMonth()+1)}-${p(d.getUTCDate())}` +
               `T${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())}-0400`;
      }
    }
    case 'alt':        return parsed.alt      ?? 0;
    case 'sats':       return parsed.sats     ?? 0;
    case 'hdop':       return parsed.hdop     ?? 0;
    case 'odometro':   return parsed.odometro ?? 0;
    case 'numero_actividad': {
      const ts         = parsed.wialon_ts ? new Date(parsed.wialon_ts).getTime() : Date.now();
      const imeiSuffix = String(unit.imei || '000000').slice(-6);
      return Number(`${ts}${imeiSuffix}`) || ts;
    }
    case 'sitrack_evento': {
      const ign = parsed.ignition === true || parsed.ignition === 1;
      return ign ? 163 : 164;
    }
    case 'timezone_chile': return 'America/Santiago';
    case 'unix_timestamp_ms': {
      return new Date(parsed.wialon_ts || new Date().toISOString()).getTime();
    }
    case 'unix_timestamp': {
      return Math.floor(new Date(parsed.wialon_ts || new Date().toISOString()).getTime() / 1000);
    }

    // ── NUEVO: dirección física (reverse geocoding) ────────────────────────
    case 'address':
      return getReverseGeocode(parsed.lat, parsed.lon); // devuelve Promise<string|null>

    case 'unit_plate': return unit.plate || '';
    case 'unit_plate_guion': {
      const p = (unit.plate || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
      if (p.length === 6) return `${p.slice(0,2)}-${p.slice(2,4)}-${p.slice(4,6)}`;
      if (p.length === 5) return `${p.slice(0,2)}-${p.slice(2,4)}-${p.slice(4,5)}`;
      return p;
    }
    case 'unit_imei':      return unit.imei        || '';
    case 'unit_name':      return unit.name        || '';
    case 'unit_rut_limpio':
      // RUT de la unidad sin puntos ni guión
      return (unit.rut || '').replace(/\./g, '').replace(/-/g, '').trim();
    case 'unit_rut':       return unit.rut         || '';
    case 'cliente_nombre': return clienteData?.nombre || unit.name || null;
    case 'cliente_rut_limpio':
      // RUT sin puntos ni guión: "96.521.450-1" → "965214501"
      return (clienteData?.rut || unit.rut || '').replace(/\./g, '').replace(/-/g, '').trim();
    case 'cliente_rut':    return clienteData?.rut    || unit.rut  || null;
    case 'plate':          return unit.plate || '';
    case 'imei':           return unit.imei  || '';
    default:               return null;
  }
}

// ─── buildPayload — ahora async para poder await campos como 'address' ────────
async function buildPayload(fieldSchema, unit, parsed, clienteData) {
  const fields = (fieldSchema || [])
    .filter(f => f.apiKey && (
      f.source === 'fixed' ||           // fuente explícita fixed
      (f.source && f.source !== '') ||  // cualquier fuente no vacía
      (f.fixedValue !== undefined && f.fixedValue !== null && f.fixedValue !== '') // source vacío pero con valor fijo
    ))
    .sort((a, b) => (a.order || 0) - (b.order || 0));

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
      missing: [], warnings: [],
    };
  }

  const obj = {}, missing = [], warnings = [];

  for (const f of fields) {
    let val;
    // Tratar como fixed si: source === 'fixed' O source está vacío pero hay fixedValue
    const isFixed = f.source === 'fixed' || ((!f.source || f.source === '') && f.fixedValue !== undefined && f.fixedValue !== null && f.fixedValue !== '');
    if (isFixed) {
      val = (f.fixedValue !== undefined && f.fixedValue !== null && f.fixedValue !== '')
        ? f.fixedValue : null;
    } else {
      const resolved = resolveSource(f.source, unit, parsed, clienteData);
      // Await si es Promise (ej: 'address' llama a getReverseGeocode)
      val = (resolved instanceof Promise) ? await resolved : resolved;
    }

    const isEmpty = val === null || val === undefined || val === '';
    if (isEmpty) {
      if (f.required) {
        missing.push({ apiKey: f.apiKey, source: f.source, label: f.label });
      } else {
        warnings.push({ apiKey: f.apiKey, source: f.source });
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
  let clienteData = {};
  try {
    if (unit.cliente_id) {
      const cachedCliente = cacheGet(_clienteCache, unit.cliente_id);
      if (cachedCliente !== undefined) {
        clienteData = cachedCliente;
      } else {
        const { rows: cr } = await query(
          'SELECT nombre, rut FROM public.clientes WHERE id = $1', [unit.cliente_id]
        );
        clienteData = cr[0] || {};
        cacheSet(_clienteCache, unit.cliente_id, clienteData, CACHE_TTL_MS);
      }
    }
  } catch (_) {}

  let assignments_rows = cacheGet(_destCache, unit.imei);
  if (assignments_rows === undefined) {
    const { rows: freshRows } = await query(`
    SELECT
      ud.shadow,
      d.id          AS dest_id,
      d.name        AS dest_name,
      d.api_url,
      d.field_schema,
      d.auth,
      d.driver_slug
    FROM public.unit_destinations ud
    JOIN public.destinations d ON d.id = ud.destination_id
    WHERE ud.imei    = $1
      AND ud.enabled = true
      AND d.enabled  = true
      AND (
        (d.api_url IS NOT NULL AND d.api_url <> '')
        OR
        (d.driver_slug IS NOT NULL AND d.driver_slug <> '')
      )
    `, [unit.imei]);
    cacheSet(_destCache, unit.imei, freshRows, CACHE_DEST_TTL_MS);
    assignments_rows = freshRows;
  }
  const assignments = assignments_rows;

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

    if (row.driver_slug) {
      if (parsed.lat === 0 && parsed.lon === 0) {
        console.warn(`[TCP] ${unit.plate} COORDS_DEBUG | lat=${parsed.lat} lon=${parsed.lon} speed=${parsed.speed} heading=${parsed.heading} alt=${parsed.alt} sats=${parsed.sats} wialon_ts=${parsed.wialon_ts} raw=${parsed.raw || 'none'}`);
      }
      if (parsed.lat === 0 && parsed.lon === 0) {
        console.warn(`[TCP] ${unit.plate} → ${row.dest_name} ⚠ coordenadas 0,0 — paquete descartado`);
        await saveEvent(unit, parsed, row.dest_id, false, 'invalid_coords_0_0');
        continue;
      }
      let forwardOk = false, forwardResp = null;
      try {
        const driver = loadDriver(row.driver_slug);
        if (!driver) throw new Error(`Driver "${row.driver_slug}" no encontrado`);

        const driverEvent = {
          imei:       unit.imei,
          lat:        parsed.lat,
          lon:        parsed.lon,
          speed:      parsed.speed,
          heading:    parsed.heading,
          alt:        parsed.alt   || 0,
          ignition:   parsed.ignition,
          engineOn:   parsed.ignition,
          odometro:   parsed.odometro  ?? 0,
          hdop:       parsed.hdop      ?? 0,
          sats:       parsed.sats      ?? 0,
          hourmeter:  parsed.hourmeter ?? 0,
          wialon_ts:  parsed.wialon_ts,
          time_epoch: parsed.wialon_ts
            ? Math.floor(new Date(parsed.wialon_ts).getTime() / 1000)
            : Math.floor(Date.now() / 1000),
        };
        const driverUnit = { imei: unit.imei, plate: unit.plate, name: unit.name, rut: unit.rut };

        let driverFieldSchema = [];
        try { driverFieldSchema = typeof row.field_schema === 'string' ? JSON.parse(row.field_schema) : (row.field_schema || []); } catch (_) {}
        let driverAuth = null;
        try { driverAuth = typeof row.auth === 'string' ? JSON.parse(row.auth) : row.auth; } catch (_) {}

        const driverRoute = { destination_id: row.dest_id, url: row.api_url, field_schema: driverFieldSchema, auth: driverAuth };

        console.log(`[TCP] ${unit.plate} → ${row.dest_name} [driver:${row.driver_slug}]`);
        const result = await driver.send({ event: driverEvent, unit: driverUnit, route: driverRoute });

        forwardOk   = result.ok === true;
        forwardResp = `${result.http_status || 0} ${result.status || ''} ${result.response_http || ''}`.trim().slice(0, 500);

        if (forwardOk) console.log(`[TCP] ${unit.plate} → ${row.dest_name} ✓ (${result.http_status})`);
        else console.error(`[TCP] ${unit.plate} → ${row.dest_name} ✗ (${result.http_status}) ${result.response_http?.slice(0,150) || ''}`);

      } catch (err) {
        forwardResp = err.message?.slice(0, 500) || 'driver_error';
        console.error(`[TCP] ${unit.plate} → ${row.dest_name} driver error:`, err.message);
      }
      await saveEvent(unit, parsed, row.dest_id, forwardOk, forwardResp);
      continue;
    }

    let fieldSchema = [];
    try { fieldSchema = typeof row.field_schema === 'string' ? JSON.parse(row.field_schema) : (row.field_schema || []); } catch (_) {}

    // buildPayload ahora es async (para resolver 'address')
    const { payload: payloadArray, missing, warnings } = await buildPayload(fieldSchema, unit, parsed, clienteData);

    if (missing.length > 0) {
      const faltantes = missing.map(f => `${f.apiKey}(${f.source})`).join(', ');
      const errMsg    = `CAMPOS_FALTANTES: ${faltantes}`;
      console.error(`[TCP] ${unit.plate} → ${row.dest_name} ✗ ${errMsg}`);
      await saveEvent(unit, parsed, row.dest_id, false, errMsg);
      continue;
    }

    if (parsed.lat === 0 && parsed.lon === 0) {
      console.warn(`[TCP] ${unit.plate} → ${row.dest_name} ⚠ coordenadas 0,0 — paquete descartado`);
      await saveEvent(unit, parsed, row.dest_id, false, 'invalid_coords_0_0');
      continue;
    }

    if (warnings.length > 0) {
      console.warn(`[TCP] ${unit.plate} → ${row.dest_name} ⚠ campos opcionales vacíos: ${warnings.map(f => f.apiKey).join(', ')}`);
    }

    let auth = null;
    try { auth = typeof row.auth === 'string' ? JSON.parse(row.auth) : row.auth; } catch (_) {}
    const authHeaders = buildAuthHeaders(auth);

    const mappedFields = fieldSchema.filter(f => f.source).length;
    const mode = mappedFields > 0 ? `mapeo(${mappedFields} campos)` : 'genérico';
    console.log(`[TCP] ${unit.plate} → ${row.dest_name} [${mode}]`);

    if (process.env.DEBUG_AUTH) {
      console.log(`[AUTH-DEBUG] ${row.dest_name} | type=${auth?.type} | token_len=${auth?.token?.length} | token_end=${auth?.token?.slice(-8)}`);
    }
    let forwardOk = false, forwardResp = null;
    const finalBody = injectAuthInBody(auth, payloadArray);
    // Log permanente del payload enviado a cada destino
    console.log(`[PAYLOAD] ${unit.plate} → ${row.dest_name} | ${JSON.stringify(finalBody).slice(0, 500)}`);

    try {
      const res = await fetch(row.api_url, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json', ...authHeaders },
        body:    JSON.stringify(finalBody),
        signal:  AbortSignal.timeout ? AbortSignal.timeout(8000) : undefined,
      });
      forwardOk   = res.ok;
      const respBody = await res.text().catch(() => '');
      forwardResp = `${res.status} | ${respBody}`.slice(0, 500);
      if (!forwardOk) console.error(`[TCP] ${unit.plate} → ${row.dest_name} ✗ (${res.status}) body: ${respBody.slice(0,200)}`);
      else            console.log(`[TCP] ${unit.plate} → ${row.dest_name} ✓ (${res.status})`);
    } catch (err) {
      forwardResp = err.message?.slice(0, 500) || 'error';
      console.error(`[TCP] ${unit.plate} → ${row.dest_name} error:`, err.message);
    }
    await saveEvent(unit, parsed, row.dest_id, forwardOk, forwardResp, finalBody?.[0] || null);
  }
}

// ─── Buffer FIFO por IMEI — ordena eventos antes de reenviar ─────────────────
const BUFFER_WINDOW_MS = 3000;
const _fifoBuffers     = new Map();

function _tsMs(wialon_ts) {
  if (!wialon_ts) return Date.now();
  const t = new Date(wialon_ts).getTime();
  return isNaN(t) ? Date.now() : t;
}

async function _flushBuffer(imei) {
  const buf = _fifoBuffers.get(imei);
  if (!buf) return;
  _fifoBuffers.delete(imei);
  buf.events.sort((a, b) => _tsMs(a.parsed.wialon_ts) - _tsMs(b.parsed.wialon_ts));
  console.log(`[FIFO] ${imei} — flush ${buf.events.length} eventos ordenados`);
  for (const { unit, parsed } of buf.events) await forwardToDestinations(unit, parsed);
}

async function enqueueEvent(unit, parsed) {
  const imei = unit.imei;
  const tsMs = _tsMs(parsed.wialon_ts);
  const buf  = _fifoBuffers.get(imei);

  if (!buf) {
    _fifoBuffers.set(imei, { lastTs: tsMs, events: null, timer: null });
    await forwardToDestinations(unit, parsed);
    return;
  }
  if (buf.events) {
    buf.events.push({ unit, parsed });
    clearTimeout(buf.timer);
    buf.timer = setTimeout(() => _flushBuffer(imei), BUFFER_WINDOW_MS);
    return;
  }
  if (tsMs < buf.lastTs - 1000) {
    console.warn(`[FIFO] ${imei} evento fuera de orden (ts=${new Date(tsMs).toISOString()} < last=${new Date(buf.lastTs).toISOString()}) — activando buffer`);
    buf.events = [{ unit, parsed }];
    buf.timer  = setTimeout(() => _flushBuffer(imei), BUFFER_WINDOW_MS);
    return;
  }
  buf.lastTs = Math.max(buf.lastTs, tsMs);
  await forwardToDestinations(unit, parsed);
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
    let protocol    = null;
    let ipsBuffer   = '';
    let rtBuffer    = Buffer.alloc(0);

    console.log(`[TCP] Nueva conexión desde ${remoteAddr}`);

    const noDataTimer = setTimeout(() => {
      console.warn(`[TCP] Sin datos en 20s desde ${remoteAddr} — cerrando`);
      socket.destroy();
    }, 20000);

    socket.on('data', async (chunk) => {
      clearTimeout(noDataTimer);

      if (protocol === null) {
        const firstByte = chunk[0];
        if (firstByte === 0x23) {
          protocol = 'ips';
          console.log(`[TCP] Protocolo: Wialon IPS (texto) desde ${remoteAddr}`);
        } else {
          protocol = 'retranslator';
          console.log(`[TCP] Protocolo: Wialon Retranslator (binario) desde ${remoteAddr}`);
        }
      }

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
            await enqueueEvent(unit, parsed);
          }
        }
      }

      if (protocol === 'retranslator') {
        rtBuffer = Buffer.concat([rtBuffer, chunk]);

        while (rtBuffer.length >= 4) {
          const packetSize = rtBuffer.readUInt32LE(0);
          if (rtBuffer.length < packetSize + 4) break;
          const packetBuf = rtBuffer.slice(0, packetSize + 4);
          rtBuffer        = rtBuffer.slice(packetSize + 4);

          console.log(`[TCP-RT] Paquete recibido: ${packetSize + 4} bytes desde ${remoteAddr}`);
          const parsed = parseRetranslatorPacket(packetBuf);
          if (!parsed) { console.warn(`[TCP-RT] Paquete no parseable desde ${remoteAddr}`); socket.write(Buffer.from([0x11])); continue; }

          console.log(`[TCP-RT] UID: ${parsed.uid} | lat: ${parsed.lat} lon: ${parsed.lon} speed: ${parsed.speed}`);
          socket.write(Buffer.from([0x11]));

          const unit = await findUnit(parsed.uid);
          if (!unit)         { console.warn(`[TCP-RT] UID/IMEI ${parsed.uid} no registrado`); continue; }
          if (!unit.enabled) { console.log(`[TCP-RT] ${unit.plate} deshabilitada`); continue; }

          sessionImei = parsed.uid;
          await enqueueEvent(unit, {
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
