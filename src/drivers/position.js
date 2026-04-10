'use strict';

/**
 * drivers/position.js
 * Driver SOAP/XML para Position GPS (Agunsa / Amazon).
 *
 * Variables de entorno Railway:
 *   POSITION_GPS   — nombre del proveedor GPS (default: SIGUELOGPS)
 *   POSITION_NET   — nombre cuenta/transportista (default: SIGUELOGPS)
 *   POSITION_USER  — usuario API (default: SIGUELOGPS)
 *   POSITION_PASS  — contraseña API (default: U01HVUVMT0dQuzE3MDI=)
 *   POSITION_SITE  — sitio cliente (default: POS)
 *   POSITION_URL   — URL del WS
 *
 * Para múltiples clientes, configurar en field_schema del destino:
 *   apiKey: position_net  → nombre transportista/cuenta del cliente
 *   apiKey: position_site → sitio del cliente
 *   apiKey: position_pass → password si difiere del global
 *   apiKey: position_user → usuario si difiere del global
 */

const WSDL_URL  = process.env.POSITION_URL  || 'https://api.gpsposition.cl/wsPositionGPS/integrationPositionGPSAgunsa.php';
const GPS_NAME  = process.env.POSITION_GPS  || 'SIGUELOGPS';
const NET_NAME  = process.env.POSITION_NET  || 'SIGUELOGPS';
const USER      = process.env.POSITION_USER || 'SIGUELOGPS';
const PASS      = process.env.POSITION_PASS || 'U01HVUVMT0dQuzE3MDI=';  // corregido
const SITE      = process.env.POSITION_SITE || 'POS';

// Cache de IMEIs ya instalados en Position (en memoria)
const _instalados = new Set();

// ── Helpers XML ───────────────────────────────────────────────────
function esc(v) {
  return String(v ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function pad2(n) { return String(n).padStart(2, '0'); }

function formatFecha(wialon_ts) {
  const d = wialon_ts ? new Date(wialon_ts) : new Date();
  if (isNaN(d)) return new Date().toISOString().replace('T', ' ').slice(0, 19);
  return `${d.getUTCFullYear()}-${pad2(d.getUTCMonth()+1)}-${pad2(d.getUTCDate())} ` +
         `${pad2(d.getUTCHours())}:${pad2(d.getUTCMinutes())}:${pad2(d.getUTCSeconds())}`;
}

// ── Construir SOAP envelopes ──────────────────────────────────────
function buildInstalarMovil(pat, imei, cfg) {
  return `<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:integrationPositionGPS" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <soapenv:Body>
    <urn:InstalarMovil soapenv:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
      <npg xsi:type="xsd:string">${esc(cfg.gps)}</npg>
      <net xsi:type="xsd:string">${esc(cfg.net)}</net>
      <pat xsi:type="xsd:string">${esc(pat)}</pat>
      <imei xsi:type="xsd:string">${esc(imei)}</imei>
      <user xsi:type="xsd:string">${esc(cfg.user)}</user>
      <pass xsi:type="xsd:string">${esc(cfg.pass)}</pass>
      <site xsi:type="xsd:string">${esc(cfg.site)}</site>
    </urn:InstalarMovil>
  </soapenv:Body>
</soapenv:Envelope>`;
}

function buildPublicarMovil(pat, imei, event, cfg) {
  const ign = (event.ignition === true || event.ignition === 1) ? '1'
            : (event.ignition === false || event.ignition === 0) ? '-1'
            : '0';
  return `<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:integrationPositionGPS" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <soapenv:Body>
    <urn:PublicarMovil soapenv:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
      <npg xsi:type="xsd:string">${esc(cfg.gps)}</npg>
      <net xsi:type="xsd:string">${esc(cfg.net)}</net>
      <pat xsi:type="xsd:string">${esc(pat)}</pat>
      <imei xsi:type="xsd:string">${esc(imei)}</imei>
      <user xsi:type="xsd:string">${esc(cfg.user)}</user>
      <pass xsi:type="xsd:string">${esc(cfg.pass)}</pass>
      <site xsi:type="xsd:string">${esc(cfg.site)}</site>
      <fec xsi:type="xsd:string">${esc(formatFecha(event.wialon_ts))}</fec>
      <lat xsi:type="xsd:string">${esc(event.lat ?? 0)}</lat>
      <lng xsi:type="xsd:string">${esc(event.lon ?? event.lng ?? 0)}</lng>
      <head xsi:type="xsd:string">${esc(Math.round(event.heading ?? 0))}</head>
      <vel xsi:type="xsd:string">${esc(Math.round(event.speed ?? 0))}</vel>
      <ign xsi:type="xsd:string">${ign}</ign>
      <pta xsi:type="xsd:string">0</pta>
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
  const t0 = Date.now();
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
  const ok      = res.ok && />\s*OK\s*<\/return>/i.test(text);
  return { ok, http_status: res.status, response_http: text.slice(0, 500), latency_ms: latency };
}

// ── Leer config del field_schema o auth del destino ───────────────
function readConfig(route) {
  const cfg = {
    gps:  GPS_NAME,
    net:  NET_NAME,
    user: USER,
    pass: PASS,
    site: SITE,
  };

  // 1. Leer del field_schema (campos fijos por destino en la UI)
  try {
    let schema = route?.field_schema || [];
    if (typeof schema === 'string') schema = JSON.parse(schema);
    for (const f of schema) {
      if (f.source === 'fixed' && f.fixedValue) {
        if (f.apiKey === 'position_net')  cfg.net  = f.fixedValue;
        if (f.apiKey === 'position_site') cfg.site = f.fixedValue;
        if (f.apiKey === 'position_user') cfg.user = f.fixedValue;
        if (f.apiKey === 'position_pass') cfg.pass = f.fixedValue;
        if (f.apiKey === 'position_gps')  cfg.gps  = f.fixedValue;
      }
    }
  } catch (_) {}

  // 2. Leer del auth del destino como fallback
  try {
    const auth = typeof route?.auth === 'string' ? JSON.parse(route.auth) : route?.auth;
    if (auth?.username && cfg.user === USER) cfg.user = auth.username;
    if (auth?.password && cfg.pass === PASS) cfg.pass = auth.password;
  } catch (_) {}

  console.log(`[position] config → net=${cfg.net} site=${cfg.site} user=${cfg.user} gps=${cfg.gps}`);
  return cfg;
}

// ── Instalar móvil si no está en cache ────────────────────────────
async function ensureInstalado(pat, imei, cfg) {
  const key = `${imei}:${cfg.net}:${cfg.site}`;
  if (_instalados.has(key)) return true;

  console.log(`[position] InstalarMovil pat=${pat} imei=${imei} net=${cfg.net} site=${cfg.site} user=${cfg.user}`);
  const xml    = buildInstalarMovil(pat, imei, cfg);
  const result = await soapCall('InstalarMovil', xml);
  // Log respuesta completa del InstalarMovil
  const instMsg = result.response_http.match(/<return[^>]*>([^<]{0,300})<\/return>/i);
  console.log(`[position] InstalarMovil resp http=${result.http_status} ok=${result.ok} msg="${instMsg?.[1] || result.response_http.slice(0,200)}"`);

  if (result.ok || /ya existe/i.test(result.response_http)) {
    _instalados.add(key);
    console.log(`[position] InstalarMovil OK (${result.latency_ms}ms)`);
    return true;
  }

  // Loguear respuesta completa para diagnóstico
  console.error(`[position] InstalarMovil FAIL (${result.http_status}): ${result.response_http.slice(0, 400)}`);

  // Algunos servidores devuelven un mensaje específico de por qué falló
  // Extraer el mensaje del XML si existe
  const msgMatch = result.response_http.match(/<return[^>]*>([^<]+)<\/return>/i);
  if (msgMatch) console.error(`[position] InstalarMovil mensaje: ${msgMatch[1]}`);

  return false;
}

// ── Función principal del driver ──────────────────────────────────
async function send({ event, unit, route }) {
  const imei = unit.imei || event.imei;
  const pat  = (unit.plate || '').toUpperCase().replace(/[^A-Z0-9]/g, '');

  if (!imei || !pat) {
    return { ok: false, http_status: 0, status: 'failed', response_http: 'Missing imei or plate' };
  }

  const cfg = readConfig(route);

  // 1. Asegurar que el móvil está instalado
  const instalado = await ensureInstalado(pat, imei, cfg);
  if (!instalado) {
    return { ok: false, http_status: 0, status: 'failed', response_http: 'InstalarMovil falló' };
  }

  // 2. Publicar posición
  const xml    = buildPublicarMovil(pat, imei, event, cfg);
  const result = await soapCall('PublicarMovil', xml);

  // Extraer mensaje del XML para el log
  const pubMsg = result.response_http.match(/<return[^>]*>([^<]{0,200})<\/return>/i);
  console.log(`[position] PublicarMovil pat=${pat} net=${cfg.net} http=${result.http_status} ok=${result.ok} msg="${pubMsg?.[1] || ''}" (${result.latency_ms}ms)`);

  // Si retorna "Móvil no registrado" — limpiar cache y reintentar
  if (!result.ok && /no registrado/i.test(result.response_http)) {
    console.warn(`[position] Móvil no registrado, reintentando InstalarMovil...`);
    const key = `${imei}:${cfg.net}:${cfg.site}`;
    _instalados.delete(key);
    const reinstalado = await ensureInstalado(pat, imei, cfg);
    if (reinstalado) {
      const retry = await soapCall('PublicarMovil', xml);
      return { ...retry, status: retry.ok ? 'ok' : 'failed' };
    }
  }

  return { ...result, status: result.ok ? 'ok' : 'failed' };
}

module.exports = { send };
