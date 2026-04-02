/**
 * src/drivers/startsee.js
 * Driver Startsee / CVX-R — POST /api/v1/gps (Bearer)
 * Body: Array<EventoGPS> ordenados del más antiguo al más nuevo
 *
 * Variables de entorno Railway:
 *   STARTSEE_URL                — URL API (default: https://startsee.cvx-r.cl/api/v1/gps)
 *   STARTSEE_TOKEN              — Bearer token (obligatorio)
 *   STARTSEE_NUMERO_INTERNO     — Número interno (default: 1)
 *   STARTSEE_CONTRATISTA        — Nombre contratista (default: SigueloGPS)
 *   STARTSEE_RUT_CONTRATISTA    — RUT contratista (default: 00000000)
 *   STARTSEE_CONDUCTOR          — Conductor (default: 000000)
 *   STARTSEE_RUT_CONDUCTOR      — RUT conductor (default: 111111111)
 *   STARTSEE_CODIGO_OPERADOR_GSM— Código operador GSM 5-6 chars (default: 73001)
 */

'use strict';

const crypto = require('crypto');

const DEFAULT_URL = 'https://startsee.cvx-r.cl/api/v1/gps';

function num(v, fb) { const n = Number(v); return Number.isFinite(n) ? n : (fb !== undefined ? fb : 0); }
function int(v, fb) { const n = parseInt(v, 10); return Number.isFinite(n) ? n : (fb !== undefined ? fb : 0); }
function str(v, fb) { if (v === null || v === undefined) return fb ?? ''; const s = String(v).trim(); return s || (fb ?? ''); }

// Hash SHA-256 corto como id_evento (string 1..40)
function makeIdEvento(imei, timeEpoch, lat, lon) {
  const base = `${imei}|${timeEpoch}|${lat}|${lon}`;
  return crypto.createHash('sha256').update(base, 'utf8').digest('hex').slice(0, 40);
}

// Epoch segundos → ISO UTC
function toIsoUtc(epochSec) {
  const s = Number.isFinite(Number(epochSec)) ? Number(epochSec) : Math.floor(Date.now() / 1000);
  return new Date(s * 1000).toISOString();
}

// Epoch ms desde wialon_ts
function toEpochSec(isoStr) {
  if (!isoStr) return Math.floor(Date.now() / 1000);
  const d = new Date(isoStr);
  return isNaN(d.getTime()) ? Math.floor(Date.now() / 1000) : Math.floor(d.getTime() / 1000);
}

async function send({ event, unit } = {}) {
  const url   = (process.env.STARTSEE_URL   || DEFAULT_URL).trim();
  const token = (process.env.STARTSEE_TOKEN || '').trim();

  if (!token) {
    console.warn('[startsee] STARTSEE_TOKEN no configurado');
    return { ok: false, status: 'skipped', http_status: 0, latency_ms: 0, response_http: 'missing_token' };
  }

  const imei  = String(event?.imei  || unit?.imei  || '').trim();
  const plate = String(unit?.plate  || unit?.name  || imei).trim();
  const lat   = num(event?.lat,  null);
  const lng   = num(event?.lon,  null);

  if (!imei) {
    console.warn('[startsee] IMEI faltante — skip');
    return { ok: true, status: 'skipped', http_status: 0, latency_ms: 0, response_http: 'no_imei' };
  }
  if (lat === null || lng === null) {
    console.warn(`[startsee] coordenadas faltantes ${imei} — skip`);
    return { ok: true, status: 'skipped', http_status: 0, latency_ms: 0, response_http: 'no_coords' };
  }

  const timeEpoch  = toEpochSec(event?.wialon_ts);
  const idEvento   = makeIdEvento(imei, timeEpoch, lat, lng);

  // Configuración desde env
  const numeroInterno  = Math.max(1, int(process.env.STARTSEE_NUMERO_INTERNO, 1));
  const contratista    = str(process.env.STARTSEE_CONTRATISTA,     'SigueloGPS');
  const rutContratista = str(process.env.STARTSEE_RUT_CONTRATISTA, '00000000');
  const conductor      = str(process.env.STARTSEE_CONDUCTOR,       '000000');
  const rutConductor   = str(process.env.STARTSEE_RUT_CONDUCTOR,   '111111111');
  const codOperador    = str(process.env.STARTSEE_CODIGO_OPERADOR_GSM, '73001');

  const payload = [{
    id_evento:                  idEvento,
    patente:                    plate,
    fecha_hora_evento:          toIsoUtc(timeEpoch),
    fecha_hora_recepcion:       new Date().toISOString(),
    latitud:                    lat,
    longitud:                   lng,
    direccion:                  int(event?.heading,  0),
    velocidad:                  int(event?.speed,    0),
    velocidad_maxima:           0,
    altitud:                    int(event?.alt,      0),
    satelites:                  int(event?.sats,     0),
    hdop:                       num(event?.hdop,     0),
    contacto:                   event?.ignition === true || event?.ignition === 1,
    tipo_evento:                0,
    imei,
    distancia_recorrida_viaje:  0,
    distancia_recorrida_total:  0,
    voltaje_bateria_vehiculo:   0,
    voltaje_bateria_gps:        0,
    tipo_dato_opcional:         0,
    dato_opcional:              {},
    // Campos requeridos por Startsee
    numero_interno:             numeroInterno,
    contratista,
    rut_contratista:            rutContratista,
    codigo_operador_gsm:        codOperador,
    gsm_signal:                 0,
    conductor,
    rut_conductor:              rutConductor,
    green_driving:              0,
    green_driving_valor:        0,
  }];

  console.log(`[startsee] enviando imei=${imei} plate=${plate} id_evento=${idEvento}`);

  const t0 = Date.now();
  let res, body;
  try {
    res  = await fetch(url, {
      method:  'POST',
      headers: {
        'Content-Type':  'application/json',
        'Authorization': 'Bearer ' + token,
        'Accept':        'application/json',
      },
      body:   JSON.stringify(payload),
      signal: AbortSignal.timeout ? AbortSignal.timeout(10000) : undefined,
    });
    body = await res.text().catch(() => '');
  } catch (err) {
    console.error(`[startsee] error de red ${imei}:`, err.message);
    return { ok: false, status: 'failed', http_status: 0, latency_ms: Date.now()-t0, response_http: err.message };
  }

  const latency_ms = Date.now() - t0;

  // Respuesta: array de resultados — resultado: OK | WARN | ERROR
  let ok = res.ok;
  let status = ok ? 'sent' : 'failed';

  try {
    const parsed = JSON.parse(body);
    const first  = Array.isArray(parsed) ? parsed[0] : parsed;
    const result = String(first?.resultado || '').toUpperCase();
    if (ok && result === 'WARN')  status = 'sent_with_warnings';
    if (ok && result === 'ERROR') { ok = false; status = 'failed'; }
  } catch (_) {}

  if (ok) {
    console.log(`[startsee] ✓ (${res.status})`);
  } else {
    console.warn(`[startsee] ✗ (${res.status}) ${body.slice(0,200)}`);
  }

  return {
    ok,
    status,
    http_status:   res.status,
    latency_ms,
    response_http: body.slice(0, 2000),
  };
}

module.exports = { send, name: 'startsee' };
