'use strict';

/**
 * drivers/position_agunsa.js
 * ─────────────────────────────────────────────────────────────────
 * Driver SOAP/XML para Position GPS (Agunsa / Amazon).
 *
 * WSDL: https://api.gpsposition.cl/wsPositionGPS/integrationPositionGPSAgunsa.php?wsdl
 *
 * Métodos:
 *   InstalarMovil  — registra el vehículo (se llama una vez por IMEI)
 *   PublicarMovil  — envía posición GPS
 *
 * Variables de entorno Railway:
 *   POSITION_GPS   — nombre del proveedor GPS  (default: SIGUELOGPS)
 *   POSITION_NET   — nombre cuenta/transportista (default: SIGUELOGPS)
 *   POSITION_USER  — usuario API               (default: SIGUELOGPS)
 *   POSITION_PASS  — contraseña API (base64 ok) (default: U0lHVUVMT0dQUzE3MDI=)
 *   POSITION_SITE  — sitio cliente             (default: POS)
 *   POSITION_URL   — URL del WS                (default: url producción)
 */

const WSDL_URL = process.env.POSITION_URL ||
  'https://api.gpsposition.cl/wsPositionGPS/integrationPositionGPSAgunsa.php';

const GPS_NAME = process.env.POSITION_GPS  || 'SIGUELOGPS';
const NET_NAME = process.env.POSITION_NET  || 'SIGUELOGPS';
const USER     = process.env.POSITION_USER || 'SIGUELOGPS';
const PASS     = process.env.POSITION_PASS || 'U0lHVUVMT0dQUzE3MDI=';
const SITE     = process.env.POSITION_SITE || 'POS';

// Cache de IMEIs ya instalados en Position (en memoria, se reinicia con el proceso)
const _instalados = new Set();

// ── Helpers XML ───────────────────────────────────────────────────
function esc(v) {
  return String(v ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function pad2(n) { return String(n).padStart(2, '0'); }

function formatFecha(wialon_ts) {
  // Formato requerido: AAAA-MM-DD HH:II:SS
  const d = wialon_ts ? new Date(wialon_ts) : new Date();
  if (isNaN(d)) return new Date().toISOString().replace('T', ' ').slice(0, 19);
  return `${d.getUTCFullYear()}-${pad2(d.getUTCMonth()+1)}-${pad2(d.getUTCDate())} ` +
         `${pad2(d.getUTCHours())}:${pad2(d.getUTCMinutes())}:${pad2(d.getUTCSeconds())}`;
}

// ── Construir SOAP envelope ───────────────────────────────────────
function buildInstalarMovil(pat, imei) {
  return `<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope
  xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
  xmlns:urn="urn:integrationPositionGPS"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <soapenv:Body>
    <urn:InstalarMovil soapenv:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
      <npg  xsi:type="xsd:string">${esc(GPS_NAME)}</npg>
      <net  xsi:type="xsd:string">${esc(NET_NAME)}</net>
      <pat  xsi:type="xsd:string">${esc(pat)}</pat>
      <imei xsi:type="xsd:string">${esc(imei)}</imei>
      <user xsi:type="xsd:string">${esc(USER)}</user>
      <pass xsi:type="xsd:string">${esc(PASS)}</pass>
      <site xsi:type="xsd:string">${esc(SITE)}</site>
    </urn:InstalarMovil>
  </soapenv:Body>
</soapenv:Envelope>`;
}

function buildPublicarMovil(pat, imei, event) {
  const ign = (event.ignition === true || event.ignition === 1) ? '1'
            : (event.ignition === false || event.ignition === 0) ? '-1'
            : '0';

  return `<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope
  xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
  xmlns:urn="urn:integrationPositionGPS"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <soapenv:Body>
    <urn:PublicarMovil soapenv:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
      <npg  xsi:type="xsd:string">${esc(GPS_NAME)}</npg>
      <net  xsi:type="xsd:string">${esc(NET_NAME)}</net>
      <pat  xsi:type="xsd:string">${esc(pat)}</pat>
      <imei xsi:type="xsd:string">${esc(imei)}</imei>
      <user xsi:type="xsd:string">${esc(USER)}</user>
      <pass xsi:type="xsd:string">${esc(PASS)}</pass>
      <site xsi:type="xsd:string">${esc(SITE)}</site>
      <fec  xsi:type="xsd:string">${esc(formatFecha(event.wialon_ts))}</fec>
      <lat  xsi:type="xsd:string">${esc(event.lat ?? 0)}</lat>
      <lng  xsi:type="xsd:string">${esc(event.lon ?? event.lng ?? 0)}</lng>
      <head xsi:type="xsd:string">${esc(Math.round(event.heading ?? 0))}</head>
      <vel  xsi:type="xsd:string">${esc(Math.round(event.speed ?? 0))}</vel>
      <ign  xsi:type="xsd:string">${ign}</ign>
      <pta  xsi:type="xsd:string">0</pta>
      <temp1 xsi:type="xsd:string">999</temp1>
      <temp2 xsi:type="xsd:string">999</temp2>
      <chof xsi:type="xsd:string"></chof>
      <other xsi:type="xsd:string"></other>
      <alarmcode xsi:type="xsd:string"></alarmcode>
      <alarm xsi:type="xsd:string"></alarm>
    </urn:PublicarMovil>
  </soapenv:Body>
</soapenv:Envelope>`;
}

// ── Llamada SOAP ──────────────────────────────────────────────────
async function soapCall(action, xmlBody) {
  const t0  = Date.now();
  const res = await fetch(WSDL_URL, {
    method:  'POST',
    headers: {
      'Content-Type': 'text/xml; charset=utf-8',
      'SOAPAction':   `"urn:integrationPositionGPS#${action}"`,
    },
    body:   xmlBody,
    signal: AbortSignal.timeout(10000),
  });

  const text    = await res.text().catch(() => '');
  const latency = Date.now() - t0;

  // Verificar resultado: buscar <return ...>OK</return> en la respuesta
  const ok = res.ok && />\s*OK\s*<\/return>/i.test(text);

  return { ok, http_status: res.status, response_http: text.slice(0, 500), latency_ms: latency };
}

// ── Instalar móvil si no está en cache ────────────────────────────
async function ensureInstalado(pat, imei) {
  const key = `${imei}`;
  if (_instalados.has(key)) return true;

  console.log(`[position_agunsa] InstalarMovil pat=${pat} imei=${imei}`);
  const xml    = buildInstalarMovil(pat, imei);
  const result = await soapCall('InstalarMovil', xml);

  if (result.ok) {
    _instalados.add(key);
    console.log(`[position_agunsa] InstalarMovil OK (${result.latency_ms}ms)`);
    return true;
  }

  // "Patente/IMEI ya existe" también es válido — ya está registrado
  if (/ya existe/i.test(result.response_http)) {
    _instalados.add(key);
    console.log(`[position_agunsa] InstalarMovil — ya existe, continuando`);
    return true;
  }

  console.error(`[position_agunsa] InstalarMovil FAIL (${result.http_status}): ${result.response_http.slice(0, 200)}`);
  return false;
}

// ── Función principal del driver ──────────────────────────────────
/**
 * @param {object} options
 * @param {object} options.event   — datos GPS del evento
 * @param {object} options.unit    — datos de la unidad (imei, plate, ...)
 * @param {object} options.route   — datos del destino
 * @returns {{ ok, http_status, status, response_http }}
 */
async function send({ event, unit }) {
  const imei = unit.imei || event.imei;
  const pat  = (unit.plate || '').toUpperCase().replace(/[^A-Z0-9]/g, '');

  if (!imei || !pat) {
    return { ok: false, http_status: 0, status: 'failed', response_http: 'Missing imei or plate' };
  }

  // 1. Asegurar que el móvil está instalado
  const instalado = await ensureInstalado(pat, imei);
  if (!instalado) {
    return { ok: false, http_status: 0, status: 'failed', response_http: 'InstalarMovil falló' };
  }

  // 2. Publicar posición
  const xml    = buildPublicarMovil(pat, imei, event);
  const result = await soapCall('PublicarMovil', xml);

  // Si retorna "Móvil no registrado" limpiar cache y reintentar una vez
  if (!result.ok && /no registrado/i.test(result.response_http)) {
    console.warn(`[position_agunsa] Móvil no registrado, reintentando InstalarMovil...`);
    _instalados.delete(imei);
    const reinstalado = await ensureInstalado(pat, imei);
    if (reinstalado) {
      const retry = await soapCall('PublicarMovil', xml);
      return { ...retry, status: retry.ok ? 'ok' : 'failed' };
    }
  }

  return { ...result, status: result.ok ? 'ok' : 'failed' };
}

module.exports = { send };
