/**
 * src/tcp-server.js
 * Recibe paquetes Wialon IPS por TCP, los parsea, guarda en gps_events
 * y reenvía a los destinos asignados vía unit_destinations.
 *
 * Usa pool.js (pg / DATABASE_URL) — igual que el resto del proyecto.
 */

'use strict';

const net         = require('net');
const { query }   = require('./db/pool');

const TCP_PORT = parseInt(process.env.TCP_PORT || '9001', 10);

// — Parser Wialon IPS ─────────────────────────────────────────────────────
// Formato: #D#date;time;lat1;lat2;lon1;lon2;speed;course;alt;sats;hdop;inputs;...
function parseWialonPacket(raw) {
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
    console.error('[TCP] parseWialonPacket error:', err.message);
    return null;
  }
}

// — Buscar unidad por IMEI ─────────────────────────────────────────────────
async function findUnit(imei) {
  const { rows } = await query(
    'SELECT imei, plate, name, enabled FROM public.units WHERE imei = $1',
    [imei]
  );
  return rows[0] || null;
}

// — Guardar evento GPS ─────────────────────────────────────────────────────
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
      destinationId || null,
      forwardOk  ?? null,
      forwardResp  || null,
      parsed.raw   || null,
    ]);
  } catch (err) {
    console.error('[TCP] saveEvent error:', err.message);
  }
}

// — Construir headers de autenticación ────────────────────────────────────
function buildAuthHeaders(auth) {
  if (!auth || !auth.type || auth.type === 'none') return {};
  if (auth.type === 'bearer') {
    return { Authorization: `Bearer ${auth.token}` };
  }
  if (auth.type === 'basic') {
    const b64 = Buffer.from(`${auth.username}:${auth.password}`).toString('base64');
    return { Authorization: `Basic ${b64}` };
  }
  if (auth.type === 'apikey') {
    return { [auth.header || 'X-Api-Key']: auth.value };
  }
  return {};
}

// — Reenviar a destinos ────────────────────────────────────────────────────
// NOTA: El SELECT no incluye d.auth directamente para ser compatible con la DB
// antes y después de aplicar la migración 013 (ADD COLUMN auth JSONB).
// En su lugar, se lee auth por separado con manejo de error graceful.
async function forwardToDestinations(unit, parsed) {
  const { rows: assignments } = await query(`
    SELECT
      ud.enabled    AS ud_enabled,
      ud.shadow,
      d.id          AS dest_id,
      d.name        AS dest_name,
      d.api_url,
      d.enabled     AS dest_enabled
    FROM  public.unit_destinations ud
    JOIN  public.destinations d ON d.id = ud.destination_id
    WHERE ud.imei      = $1
      AND ud.enabled   = true
      AND d.enabled    = true
      AND d.api_url    IS NOT NULL
      AND d.api_url    <> ''
  `, [unit.imei]);

  if (!assignments.length) {
    console.log(`[TCP] ${unit.plate} — sin destinos activos asignados`);
    // Guardar igualmente para mantener historial GPS
    await saveEvent(unit, parsed, null, null, null);
    return;
  }

  for (const row of assignments) {
    const isShadow = row.shadow === true;

    if (isShadow) {
      console.log(`[TCP] ${unit.plate} → ${row.dest_name} [SHADOW]`);
      await saveEvent(unit, parsed, row.dest_id, null, 'shadow');
      continue;
    }

    // Leer auth del destino por separado — graceful si la columna no existe aún
    let authHeaders = {};
    try {
      const { rows: destRows } = await query(
        'SELECT auth FROM public.destinations WHERE id = $1',
        [row.dest_id]
      );
      if (destRows[0]?.auth) {
        authHeaders = buildAuthHeaders(destRows[0].auth);
      }
    } catch (_) {
      // Columna auth no existe todavía — continúa sin headers de auth
    }

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

    let forwardOk   = false;
    let forwardResp = null;

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

// — Servidor TCP ──────────────────────────────────────────────────────────
function startTcpServer() {
  if (process.env.TCP_ENABLED !== 'true') {
    console.log('[TCP] TCP_ENABLED != true — servidor no iniciado');
    return;
  }

  const server = net.createServer((socket) => {
    let sessionImei = null;
    let buffer      = '';

    socket.on('data', async (chunk) => {
      buffer += chunk.toString('ascii');
      const lines = buffer.split('\r\n');
      buffer = lines.pop(); // fragmento incompleto

      for (const line of lines) {
        if (!line.trim()) continue;
        const parsed = parseWialonPacket(line);
        if (!parsed) continue;

        if (parsed.type === 'login') {
          sessionImei = parsed.imei;
          socket.write('#AL#1\r\n');
          console.log(`[TCP] Login IMEI: ${sessionImei}`);
          continue;
        }

        if (parsed.type === 'data') {
          socket.write('#AD#1\r\n');
          if (!sessionImei) { console.warn('[TCP] Datos sin login'); continue; }

          const unit = await findUnit(sessionImei);
          if (!unit)         { console.warn(`[TCP] IMEI ${sessionImei} no registrado`); continue; }
          if (!unit.enabled) { console.log(`[TCP] ${unit.plate} deshabilitada`); continue; }

          await forwardToDestinations(unit, parsed);
        }
      }
    });

    socket.on('error', (err) => console.error('[TCP] Socket error:', err.message));
    socket.on('close', ()    => console.log(`[TCP] Conexión cerrada${sessionImei ? ' IMEI:'+sessionImei : ''}`));
  });

  server.listen(TCP_PORT, '0.0.0.0', () => {
    console.log(`[TCP] Servidor escuchando en puerto ${TCP_PORT}`);
  });

  server.on('error', (err) => console.error('[TCP] Server error:', err.message));
  return server;
}

module.exports = { startTcpServer };
