/**
 * src/drivers/qmgps.js
 * Driver QAnalytics/QMGPS — WebService SOAP/ASMX
 * Método: WM_INS_REPORTE_CLASS
 *
 * Variables de entorno Railway:
 *   QMGPS_ENDPOINT  — URL WebService (default: http://ww3.qanalytics.cl/gps_test/service.asmx)
 *   QMGPS_USER      — Usuario (default: WS_test)
 *   QMGPS_PASS      — Password (default: $$WS17)
 *   QMGPS_TRANS     — Nombre transporte (default: N/A)
 */

'use strict';

const DEFAULT_ENDPOINT = process.env.QMGPS_ENDPOINT || 'http://ww3.qanalytics.cl/gps_test/service.asmx';
const SOAP_ACTION      = 'http://tempuri.org/WM_INS_REPORTE_CLASS';

function xmlEscape(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&apos;');
}

function toInt(v, fb) {
  const n = Number(v);
  return Number.isFinite(n) ? Math.trunc(n) : (fb !== undefined ? fb : 0);
}

function toDec(v, fb) {
  const n = Number(v);
  return Number.isFinite(n) ? n : (fb !== undefined ? fb : 0);
}

function stripPlate(plate) {
  return String(plate || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
}

// Hora local Chile: "DD-MM-YYYY HH:MM:SS"
function toChileLocal(isoStr) {
  const d = isoStr ? new Date(isoStr) : new Date();
  try {
    const loc = new Date(d.toLocaleString('en-US', { timeZone: 'America/Santiago' }));
    const p   = n => String(n).padStart(2, '0');
    return `${p(loc.getDate())}-${p(loc.getMonth()+1)}-${loc.getFullYear()} ${p(loc.getHours())}:${p(loc.getMinutes())}:${p(loc.getSeconds())}`;
  } catch (_) {
    const loc = new Date(d.getTime() - 3 * 3600 * 1000);
    const p   = n => String(n).padStart(2, '0');
    return `${p(loc.getUTCDate())}-${p(loc.getUTCMonth()+1)}-${loc.getUTCFullYear()} ${p(loc.getUTCHours())}:${p(loc.getUTCMinutes())}:${p(loc.getUTCSeconds())}`;
  }
}

function buildDatosXml(row) {
  return '<Datos>' +
    '<ID_REG>'         + xmlEscape(row.ID_REG)  + '</ID_REG>'         +
    '<LATITUD>'        + row.LATITUD             + '</LATITUD>'        +
    '<LONGITUD>'       + row.LONGITUD            + '</LONGITUD>'       +
    '<VELOCIDAD>'      + row.VELOCIDAD           + '</VELOCIDAD>'      +
    '<SENTIDO>'        + row.SENTIDO             + '</SENTIDO>'        +
    '<FH_DATO>'        + xmlEscape(row.FH_DATO)  + '</FH_DATO>'        +
    '<PLACA>'          + xmlEscape(row.PLACA)    + '</PLACA>'          +
    '<CANT_SATELITES>' + row.CANT_SATELITES      + '</CANT_SATELITES>' +
    '<HDOP>'           + row.HDOP               + '</HDOP>'           +
    '<TEMP1>'          + row.TEMP1              + '</TEMP1>'          +
    '<TEMP2>'          + row.TEMP2              + '</TEMP2>'          +
    '<TEMP3>'          + row.TEMP3              + '</TEMP3>'          +
    '<SENSORA_1>'      + row.SENSORA_1          + '</SENSORA_1>'      +
    '<AP>'             + row.AP                 + '</AP>'             +
    '<IGNICION>'       + row.IGNICION           + '</IGNICION>'       +
    '<PANICO>'         + row.PANICO             + '</PANICO>'         +
    '<SENSORD_1>'      + row.SENSORD_1          + '</SENSORD_1>'      +
    '<TRANS>'          + xmlEscape(row.TRANS)   + '</TRANS>'          +
    '</Datos>';
}

// Auth en soap:Header, datos en Tabla > Datos (DataTable)
function buildSoapEnvelope(user, pass, datosXml) {
  return '<?xml version="1.0" encoding="utf-8"?>' +
    '<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ' +
    'xmlns:xsd="http://www.w3.org/2001/XMLSchema" ' +
    'xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">' +
      '<soap:Header>' +
        '<Authentication xmlns="http://tempuri.org/">' +
          '<Usuario>' + xmlEscape(user) + '</Usuario>' +
          '<Clave>'   + xmlEscape(pass) + '</Clave>'   +
        '</Authentication>' +
      '</soap:Header>' +
      '<soap:Body>' +
        '<WM_INS_REPORTE_CLASS xmlns="http://tempuri.org/">' +
          '<Tabla><NewDataSet>' + datosXml + '</NewDataSet></Tabla>' +
        '</WM_INS_REPORTE_CLASS>' +
      '</soap:Body>' +
    '</soap:Envelope>';
}

async function send({ event, unit } = {}) {
  const endpoint = DEFAULT_ENDPOINT;
  const user     = (process.env.QMGPS_USER  || 'WS_test').trim();
  const pass     = (process.env.QMGPS_PASS  || '$$WS17').trim();
  const trans    = (process.env.QMGPS_TRANS || 'N/A').trim();

  const imei  = String(event?.imei  || unit?.imei  || '').trim();
  const plate = stripPlate(unit?.plate || unit?.name || '') || 'SINPLACA';
  const lat   = toDec(event?.lat, null);
  const lng   = toDec(event?.lon, null);

  if (!imei) {
    console.warn('[qmgps] IMEI faltante — skip');
    return { ok: true, status: 'skipped', http_status: 0, latency_ms: 0, response_http: 'no_imei' };
  }
  if (lat === null || lng === null) {
    console.warn(`[qmgps] coordenadas faltantes ${imei} — skip`);
    return { ok: true, status: 'skipped', http_status: 0, latency_ms: 0, response_http: 'no_coords' };
  }

  const ignicion = (event?.ignition === true || event?.ignition === 1) ? 1
                 : (event?.ignition === false || event?.ignition === 0) ? 0 : -1;

  const row = {
    ID_REG:         imei,
    LATITUD:        lat.toFixed(6),
    LONGITUD:       lng.toFixed(6),
    VELOCIDAD:      toInt(event?.speed,   0),
    SENTIDO:        toInt(event?.heading, 0),
    FH_DATO:        toChileLocal(event?.wialon_ts),
    PLACA:          plate,
    CANT_SATELITES: toInt(event?.sats, 0),
    HDOP:           toInt(event?.hdop, 0),
    TEMP1:          999,
    TEMP2:          999,
    TEMP3:          999,
    SENSORA_1:      999,
    AP:             -1,
    IGNICION:       ignicion,
    PANICO:         -1,
    SENSORD_1:      -1,
    TRANS:          trans,
  };

  const datosXml = buildDatosXml(row);
  const envelope = buildSoapEnvelope(user, pass, datosXml);

  console.log(`[qmgps] enviando imei=${imei} plate=${plate} fh=${row.FH_DATO}`);

  const t0 = Date.now();
  let res, body;
  try {
    res  = await fetch(endpoint, {
      method:  'POST',
      headers: {
        'Content-Type': 'text/xml; charset=utf-8',
        'SOAPAction':   '"' + SOAP_ACTION + '"',  // SOAP 1.1 requiere comillas en SOAPAction
        'User-Agent':   'integraciones-siguelogps/1.0',
      },
      body:   envelope,
      signal: AbortSignal.timeout ? AbortSignal.timeout(10000) : undefined,
    });
    body = await res.text().catch(() => '');
  } catch (err) {
    console.error(`[qmgps] error de red ${imei}:`, err.message);
    return { ok: false, status: 'failed', http_status: 0, latency_ms: Date.now()-t0, response_http: err.message };
  }

  const latency_ms  = Date.now() - t0;
  const looksHtml   = /<html[\s>]/i.test(body);

  // Respuestas: CORRECTO, ERROR DE SESION, ERROR INSERCION
  const ok = res.ok &&
    /(CORRECTO|INSERCI[ÓO]N\s+CORRECTA|INSERCION\s+CORRECTA)/i.test(body) &&
    !/ERROR/i.test(body);

  if (ok) {
    console.log(`[qmgps] ✓ (${res.status})`);
  } else {
    console.warn(`[qmgps] ✗ (${res.status}) ${body.slice(0,200)}`);
  }

  return {
    ok,
    status:        ok ? 'sent' : 'failed',
    http_status:   res.status,
    latency_ms,
    response_http: body.slice(0, 2000),
    error:         ok ? null : looksHtml ? 'soap_returned_html' : res.ok ? 'ws_error' : `http_${res.status}`,
  };
}

module.exports = { send, name: 'qmgps' };
