'use strict';

/**
 * src/drivers/unigis.js
 * ─────────────────────────────────────────────────────────────────
 * Driver SOAP para Unigis MAPI — método LoginYInsertarEvento
 *
 * WSDL: https://hub.unisolutions.com.ar/hub/unigis/MAPI/SOAP/gps/service.asmx
 * Op:   LoginYInsertarEvento
 *
 * Variables de entorno Railway:
 *   UNIGIS_URL      — endpoint SOAP (default: URL producción)
 *   UNIGIS_USER     — SystemUser  (default: siguelo)
 *   UNIGIS_PASS     — Password    (default: EJC582gsy)
 *   UNIGIS_DOMINIO  — Dominio asignado por Unigis (requerido por cliente)
 *   UNIGIS_CODIGO   — Código de evento (default: 1)
 */

const ENDPOINT    = process.env.UNIGIS_URL     || 'https://hub.unisolutions.com.ar/hub/unigis/MAPI/SOAP/gps/service.asmx';
const SOAP_ACTION = 'http://unisolutions.com.ar/LoginYInsertarEvento';

const USER    = process.env.UNIGIS_USER    || 'siguelo';
const PASS    = process.env.UNIGIS_PASS    || 'EJC582gsy';
const DOMINIO = process.env.UNIGIS_DOMINIO || '';
const CODIGO  = process.env.UNIGIS_CODIGO  || '1';

// ── Helpers ───────────────────────────────────────────────────────
function esc(v) {
  return String(v ?? '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&apos;');
}

function pad2(n) { return String(n).padStart(2, '0'); }

/**
 * Formatea fecha en UTC-4 (requerimiento Unigis).
 * Resta 4 horas al timestamp UTC antes de formatear.
 * Resultado: "YYYY-MM-DDTHH:MM:SS" en hora UTC-4.
 *
 * Ejemplo:
 *   UTC  2026-04-27T14:00:00Z  →  UTC-4  2026-04-27T10:00:00
 */
function toXsdDateTimeUTC4(wialon_ts) {
  const d = wialon_ts ? new Date(wialon_ts) : new Date();
  if (isNaN(d)) {
    // Fallback: hora actual menos 4 horas
    const now = new Date(Date.now() - 4 * 3600 * 1000);
    return now.toISOString().slice(0, 19);
  }
  // Restar 4 horas (UTC-4)
  const utc4 = new Date(d.getTime() - 4 * 3600 * 1000);
  return `${utc4.getUTCFullYear()}-${pad2(utc4.getUTCMonth()+1)}-${pad2(utc4.getUTCDate())}` +
         `T${pad2(utc4.getUTCHours())}:${pad2(utc4.getUTCMinutes())}:${pad2(utc4.getUTCSeconds())}`;
}

// ── Construir envelope SOAP 1.1 ───────────────────────────────────
function buildEnvelope({ user, pass, dominio, nroSerie, codigo, lat, lon, alt, vel, fechaEvento, fechaRecepcion }) {
  return `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xmlns:xsd="http://www.w3.org/2001/XMLSchema"
  xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <LoginYInsertarEvento xmlns="http://unisolutions.com.ar/">
      <SystemUser>${esc(user)}</SystemUser>
      <Password>${esc(pass)}</Password>
      <Dominio>${esc(dominio)}</Dominio>
      <NroSerie>${esc(nroSerie)}</NroSerie>
      <Codigo>${esc(codigo)}</Codigo>
      <Latitud>${lat}</Latitud>
      <Longitud>${lon}</Longitud>
      <Altitud>${alt}</Altitud>
      <Velocidad>${vel}</Velocidad>
      <FechaHoraEvento>${esc(fechaEvento)}</FechaHoraEvento>
      <FechaHoraRecepcion>${esc(fechaRecepcion)}</FechaHoraRecepcion>
    </LoginYInsertarEvento>
  </soap:Body>
</soap:Envelope>`;
}

// ── Parsear resultado entero de la respuesta ──────────────────────
function parseResult(xml) {
  const m = xml.match(/<LoginYInsertarEventoResult[^>]*>(-?\d+)<\/LoginYInsertarEventoResult>/i);
  return m ? parseInt(m[1], 10) : null;
}

// ── Función principal del driver ──────────────────────────────────
async function send({ event, unit, route }) {
  const imei     = unit.imei  || event.imei || '';
  const plate    = (unit.plate || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
  const nroSerie = plate || imei;

  if (!nroSerie) {
    return { ok: false, http_status: 0, status: 'failed', response_http: 'Missing plate/imei' };
  }

  // Leer dominio y codigo desde field_schema si están configurados como fixed
  let dominio = DOMINIO;
  let codigo  = CODIGO;
  try {
    const schema = route?.field_schema || [];
    for (const f of schema) {
      if (f.source === 'fixed') {
        if (f.apiKey === 'Dominio' && f.fixedValue) dominio = f.fixedValue;
        if (f.apiKey === 'Codigo'  && f.fixedValue) codigo  = f.fixedValue;
      }
    }
  } catch (_) {}

  const now = new Date().toISOString();

  // FIX: ambas fechas en UTC-4 según requerimiento Unigis
  const fechaEvento    = toXsdDateTimeUTC4(event.wialon_ts || now);
  const fechaRecepcion = toXsdDateTimeUTC4(now);

  console.log(`[unigis] fechaEvento=${fechaEvento} fechaRecepcion=${fechaRecepcion} (UTC-4)`);

  const xml = buildEnvelope({
    user:   USER,
    pass:   PASS,
    dominio,
    nroSerie,
    codigo,
    lat:    event.lat   ?? 0,
    lon:    event.lon   ?? event.lng ?? 0,
    alt:    event.alt   ?? 0,
    vel:    event.speed ?? 0,
    fechaEvento,
    fechaRecepcion,
  });

  const t0 = Date.now();
  let resText = '';
  let httpStatus = 0;

  try {
    const res = await fetch(ENDPOINT, {
      method:  'POST',
      headers: {
        'Content-Type': 'text/xml; charset=utf-8',
        'SOAPAction':   `"${SOAP_ACTION}"`,
      },
      body:   xml,
      signal: AbortSignal.timeout(10000),
    });

    httpStatus = res.status;
    resText    = await res.text().catch(() => '');
    const latency = Date.now() - t0;

    if (!res.ok) {
      console.error(`[unigis] HTTP ${httpStatus} — ${resText.slice(0, 200)}`);
      return { ok: false, http_status: httpStatus, status: 'failed', response_http: resText.slice(0, 500), latency_ms: latency };
    }

    const resultCode = parseResult(resText);

    if (resultCode === null) {
      const looksLikeHtml = /<html/i.test(resText);
      console.error(`[unigis] Respuesta no parseable (${looksLikeHtml ? 'HTML' : 'XML inesperado'}): ${resText.slice(0, 200)}`);
      return { ok: false, http_status: httpStatus, status: 'failed', response_http: resText.slice(0, 500), latency_ms: latency };
    }

    const ok = resultCode > 0;

    if (ok) {
      console.log(`[unigis] ✓ nroSerie=${nroSerie} eventoId=${resultCode} (${latency}ms)`);
    } else {
      console.error(`[unigis] ✗ nroSerie=${nroSerie} result=${resultCode} (${latency}ms)`);
    }

    return {
      ok,
      http_status:   httpStatus,
      status:        ok ? 'ok' : 'failed',
      response_http: resText.slice(0, 500),
      latency_ms:    latency,
    };

  } catch (err) {
    const latency = Date.now() - t0;
    console.error(`[unigis] Error fetch:`, err.message);
    return {
      ok:            false,
      http_status:   0,
      status:        'failed',
      response_http: err.message?.slice(0, 500) || 'fetch_error',
      latency_ms:    latency,
    };
  }
}

module.exports = { send };
