// src/tcp-server.js
// Servidor TCP que recibe paquetes GPS en protocolo Wialon IPS,
// guarda eventos en gps_events y reenvía a destinos configurados.
//
// CORRECCIONES vs versión anterior:
//  - forwardToDestinations: query via unit_destinations (JOIN correcto)
//  - buildAuthHeaders: construye header dinámico desde destinations.auth
//  - Sin SKYNAV_TOKEN hardcodeado; cada destino tiene su propia auth
//  - Modo shadow: registra pero no envía

'use strict';

const net     = require('net');
const { createClient } = require('@supabase/supabase-js');

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

const TCP_PORT = parseInt(process.env.TCP_PORT || '9001', 10);

// ── Parser protocolo Wialon IPS ──────────────────────────────────────────────
// Formato: #D#date;time;lat1;lat2;lon1;lon2;speed;course;alt;sats;hdop;inputs;outputs;adc;ibutton;params\r\n
function parseWialonPacket(raw) {
  try {
    const str = raw.toString('ascii').trim();
    if (!str.startsWith('#')) return null;

    const parts = str.split('#').filter(Boolean);
    const type  = parts[0];  // D, SD, L, etc.

    if (type === 'L') {
      // Login packet: #L#imei;pass\r\n
      const body = parts[1]?.split(';') || [];
      return { type: 'login', imei: body[0]?.trim(), pass: body[1]?.trim() };
    }

    if (type === 'D' || type === 'SD') {
      const body = parts[1]?.split(';') || [];
      // date;time;lat1;lat2;lon1;lon2;speed;course;alt;sats;hdop;inputs;outputs;adc;ibutton;params
      const [date, time, lat1, lat2, lon1, lon2, speed, course, alt, sats, hdop, inputs] = body;

      const lat = parseFloat(lat1) + parseFloat(lat2) / 60;
      const lon = parseFloat(lon1) + parseFloat(lon2) / 60;

      // Ignorar lecturas inválidas
      if (isNaN(lat) || isNaN(lon)) return null;

      // Detectar ignición en inputs (bit 0)
      const inputsInt = parseInt(inputs || '0', 10);
      const ignition  = !!(inputsInt & 1);

      // Parsear timestamp
      let wialon_ts = null;
      try {
        if (date && time) {
          const [d, m, y] = date.split('.');
          const [h, mi, s] = time.split(':');
          wialon_ts = new Date(`20${y}-${m}-${d}T${h}:${mi}:${s}Z`).toISOString();
        }
      } catch (_) {}

      return {
        type:      'data',
        lat:       parseFloat(lat.toFixed(6)),
        lon:       parseFloat(lon.toFixed(6)),
        speed:     parseFloat(speed || '0'),
        heading:   parseFloat(course || '0'),
        ignition,
        wialon_ts,
        raw:       str,
      };
    }

    return null;
  } catch (err) {
    console.error('[TCP] parseWialonPacket error:', err.message);
    return null;
  }
}

// ── Buscar unidad por IMEI ───────────────────────────────────────────────────
async function findUnit(imei) {
  const { data, error } = await supabase
    .from('units')
    .select('imei, plate, name, enabled, cliente_id')
    .eq('imei', imei)
    .single();

  if (error || !data) return null;
  return data;
}

// ── Guardar evento GPS ───────────────────────────────────────────────────────
async function saveEvent(unit, parsed, destinationId, forwardOk, forwardResp) {
  const { error } = await supabase.from('gps_events').insert({
    plate:          unit.plate,
    imei:           unit.imei,
    lat:            parsed.lat,
    lon:            parsed.lon,
    speed:          parsed.speed,
    heading:        parsed.heading,
    ignition:       parsed.ignition,
    wialon_ts:      parsed.wialon_ts,
    destination_id: destinationId || null,
    forward_ok:     forwardOk ?? null,
    forward_resp:   forwardResp || null,
    raw_hex:        parsed.raw || null,
  });
  if (error) console.error('[TCP] saveEvent error:', error.message);
}

// ── Construir headers de autenticación ──────────────────────────────────────
// auth viene del campo JSONB destinations.auth
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

// ── Reenviar a destinos ──────────────────────────────────────────────────────
// Query correcta: unit_destinations (JOIN) → destinations
// Soporta múltiples destinos por unidad.
async function forwardToDestinations(unit, parsed) {
  // Buscar destinos activos asignados a esta unidad
  const { data: assignments, error } = await supabase
    .from('unit_destinations')
    .select(`
      enabled,
      shadow,
      notes,
      destination:destination_id (
        id,
        name,
        api_url,
        driver_slug,
        auth,
        enabled
      )
    `)
    .eq('imei', unit.imei)
    .eq('enabled', true);

  if (error) {
    console.error('[TCP] forwardToDestinations query error:', error.message);
    return;
  }

  if (!assignments || assignments.length === 0) {
    console.log(`[TCP] ${unit.plate} — sin destinos asignados`);
    return;
  }

  for (const row of assignments) {
    const dest = row.destination;

    // Saltar si el destino está deshabilitado globalmente
    if (!dest || !dest.enabled || !dest.api_url) continue;

    const isShadow = row.shadow === true;

    // Payload GPS estándar
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

    if (isShadow) {
      // Modo shadow: solo registrar, no enviar
      console.log(`[TCP] ${unit.plate} → ${dest.name} [SHADOW] (no enviado)`);
      await saveEvent(unit, parsed, dest.id, null, 'shadow');
      continue;
    }

    // Construir headers: auth dinámica + content-type
    const authHeaders = buildAuthHeaders(dest.auth);
    const headers = {
      'Content-Type': 'application/json',
      ...authHeaders,
    };

    let forwardOk   = false;
    let forwardResp = null;

    try {
      const res = await fetch(dest.api_url, {
        method:  'POST',
        headers,
        body:    JSON.stringify(payload),
        signal:  AbortSignal.timeout(8000),  // 8s timeout
      });

      forwardOk   = res.ok;
      forwardResp = `${res.status} ${res.statusText}`.slice(0, 500);

      console.log(`[TCP] ${unit.plate} → ${dest.name} ${forwardOk ? '✓' : '✗'} (${res.status})`);
    } catch (err) {
      forwardResp = err.message?.slice(0, 500) || 'error';
      console.error(`[TCP] ${unit.plate} → ${dest.name} error:`, err.message);
    }

    await saveEvent(unit, parsed, dest.id, forwardOk, forwardResp);
  }
}

// ── Servidor TCP ─────────────────────────────────────────────────────────────
function startTcpServer() {
  if (process.env.TCP_ENABLED !== 'true') {
    console.log('[TCP] TCP_ENABLED no está en true — servidor no iniciado');
    return;
  }

  const server = net.createServer((socket) => {
    let sessionImei = null;
    let buffer      = '';

    socket.on('data', async (chunk) => {
      buffer += chunk.toString('ascii');
      const lines = buffer.split('\r\n');
      buffer = lines.pop();  // guardar fragmento incompleto

      for (const line of lines) {
        if (!line.trim()) continue;

        const parsed = parseWialonPacket(line);
        if (!parsed) continue;

        if (parsed.type === 'login') {
          sessionImei = parsed.imei;
          socket.write('#AL#1\r\n');  // respuesta de login OK
          console.log(`[TCP] Login IMEI: ${sessionImei}`);
          continue;
        }

        if (parsed.type === 'data') {
          socket.write('#AD#1\r\n');  // ACK de datos

          if (!sessionImei) {
            console.warn('[TCP] Paquete de datos sin login previo');
            continue;
          }

          const unit = await findUnit(sessionImei);
          if (!unit) {
            console.warn(`[TCP] IMEI ${sessionImei} no registrado`);
            continue;
          }

          if (!unit.enabled) {
            console.log(`[TCP] ${unit.plate} deshabilitada — ignorando`);
            continue;
          }

          // Reenviar a todos los destinos asignados (multi-destino)
          await forwardToDestinations(unit, parsed);
        }
      }
    });

    socket.on('error', (err) => {
      console.error('[TCP] Socket error:', err.message);
    });

    socket.on('close', () => {
      console.log(`[TCP] Conexión cerrada${sessionImei ? ' IMEI: ' + sessionImei : ''}`);
    });
  });

  server.listen(TCP_PORT, '0.0.0.0', () => {
    console.log(`[TCP] Servidor escuchando en puerto ${TCP_PORT}`);
  });

  server.on('error', (err) => {
    console.error('[TCP] Server error:', err.message);
  });

  return server;
}

module.exports = { startTcpServer };
