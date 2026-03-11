/**
 * src/routes/gps-proxy.js
 * ─────────────────────────────────────────────────────────────────
 * Proxy GPS con modo dual (migración en paralelo con Fly.io):
 *
 *   MODO LOCAL (GPS_SOURCE=local — por defecto):
 *     Lee datos desde public.gps_events en Supabase.
 *     Es el modo objetivo — sin dependencia de Fly.
 *
 *   MODO FLY (GPS_SOURCE=fly):
 *     Llama al servidor Fly.io legacy.
 *     Mantener activo SOLO durante la transición.
 *
 * Una vez que el TCP server en Railway esté recibiendo datos
 * y verificado en producción, eliminar el bloque FLY y la
 * variable GPS_SOURCE.
 * ─────────────────────────────────────────────────────────────────
 */

'use strict';

const express = require('express');
const { pool } = require('../db/pool');

const router = express.Router();

// ── Config ────────────────────────────────────────────────────────
const GPS_SOURCE = process.env.GPS_SOURCE || 'local'; // 'local' | 'fly'
const GPS_FLY    = process.env.GPS_FLY_URL || 'https://integraciones-siguelogps-v2.fly.dev';

// Cuántos eventos recientes devolver en last-responses
const HISTORY_LIMIT = parseInt(process.env.GPS_HISTORY_LIMIT || '50', 10);

// Umbral en minutos para considerar una unidad "transmitiendo"
const TX_ACTIVE_MINUTES = parseInt(process.env.GPS_TX_ACTIVE_MINUTES || '15', 10);

console.log(`[gps-proxy] Modo: ${GPS_SOURCE.toUpperCase()}`);

// ── Helper: leer desde Supabase ───────────────────────────────────

async function getUnitStatusLocal(plate) {
  const { rows } = await pool.query(
    `SELECT
       received_at,
       wialon_ts,
       EXTRACT(EPOCH FROM (now() - received_at)) / 60  AS age_minutes
     FROM public.gps_events
     WHERE UPPER(plate) = UPPER($1)
     ORDER BY received_at DESC
     LIMIT 1`,
    [plate]
  );

  if (!rows.length) {
    return {
      isTransmitting:      false,
      tcpLastAt:           null,
      tcpAgeMinutes:       null,
      activeWindowMinutes: TX_ACTIVE_MINUTES,
    };
  }

  const r      = rows[0];
  const ageMin = parseFloat(r.age_minutes);

  return {
    isTransmitting:      ageMin <= TX_ACTIVE_MINUTES,
    tcpLastAt:           r.received_at,
    tcpAgeMinutes:       parseFloat(ageMin.toFixed(1)),
    activeWindowMinutes: TX_ACTIVE_MINUTES,
  };
}

async function getLastResponsesLocal(plate) {
  const { rows } = await pool.query(
    `SELECT
       id,
       plate,
       lat,
       lon,
       speed,
       heading,
       ignition,
       wialon_ts,
       received_at,
       destination_id,
       forward_ok   AS ok,
       forward_resp AS response
     FROM public.gps_events
     WHERE UPPER(plate) = UPPER($1)
     ORDER BY received_at DESC
     LIMIT $2`,
    [plate, HISTORY_LIMIT]
  );

  // Mismo formato que devolvía Fly.io — no rompe el frontend
  const results = rows.map(r => ({
    at:             r.received_at,
    destination_id: r.destination_id || null,
    ok:             r.ok ?? null,
    response:       r.response || null,
    tx: {
      lat:          r.lat     != null ? parseFloat(r.lat)     : null,
      lon:          r.lon     != null ? parseFloat(r.lon)     : null,
      speed:        r.speed   != null ? parseFloat(r.speed)   : null,
      heading:      r.heading != null ? parseFloat(r.heading) : null,
      ignition:     r.ignition,
      fechaHoraISO: r.wialon_ts || r.received_at,
    },
  }));

  return { results };
}

// ── Helper: Fly legacy ────────────────────────────────────────────

async function getFromFly(endpoint, plate) {
  const url = `${GPS_FLY}/api/${endpoint}?plate=${encodeURIComponent(plate.toUpperCase())}`;
  const res  = await fetch(url, {
    headers: { Accept: 'application/json' },
    signal:  AbortSignal.timeout(10000),
  });
  const text = await res.text();
  if (!text?.trim()) return null;
  try { return JSON.parse(text); } catch { return null; }
}

// ── Middleware JWT admin ──────────────────────────────────────────

function verifyAdminJwt(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer '))
    return res.status(401).json({ error: 'No autorizado.' });

  const jwt = require('jsonwebtoken');
  try {
    const payload = jwt.verify(auth.slice(7), process.env.JWT_SECRET);
    if (!['admin', 'operador'].includes(payload.role))
      return res.status(403).json({ error: 'Sin permisos.' });
    req.jwtPayload = payload;
    next();
  } catch {
    return res.status(401).json({ error: 'Sesión expirada.' });
  }
}

// ── GET /gps/admin?plate=XXX ──────────────────────────────────────

router.get('/admin', verifyAdminJwt, async (req, res) => {
  const { plate } = req.query;
  if (!plate) return res.status(400).json({ error: 'Falta plate.' });

  try {
    if (GPS_SOURCE === 'fly') {
      const [status, responses] = await Promise.all([
        getFromFly('unit-status',    plate),
        getFromFly('last-responses', plate),
      ]);
      return res.json({ status, responses, _source: 'fly' });
    }

    const [status, responses] = await Promise.all([
      getUnitStatusLocal(plate),
      getLastResponsesLocal(plate),
    ]);
    res.json({ status, responses, _source: 'local' });

  } catch (e) {
    console.error('[gps-proxy/admin] error:', e.message);
    res.status(502).json({ error: 'Error consultando datos GPS.' });
  }
});

// ── GET /gps/unit-status?token=xxx&plate=yyy ──────────────────────

router.get('/unit-status', async (req, res) => {
  const { token, plate } = req.query;
  if (!token || !plate)
    return res.status(400).json({ error: 'Faltan parámetros token y plate.' });

  const { rows } = await pool.query(
    `SELECT c.id FROM clientes c
     JOIN units u ON u.cliente_id = c.id
     WHERE c.token = $1 AND c.enabled = true AND UPPER(u.plate) = UPPER($2)
     LIMIT 1`,
    [token, plate]
  );
  if (!rows.length)
    return res.status(403).json({ error: 'Patente no autorizada para este token.' });

  try {
    if (GPS_SOURCE === 'fly') {
      const data = await getFromFly('unit-status', plate);
      if (!data) return res.status(502).json({ error: 'El servidor GPS no devolvió datos.' });
      return res.json(data);
    }
    res.json(await getUnitStatusLocal(plate));
  } catch (e) {
    console.error('[gps-proxy/unit-status] error:', e.message);
    res.status(502).json({ error: 'Error consultando estado GPS.' });
  }
});

// ── GET /gps/last-responses?token=xxx&plate=yyy ───────────────────

router.get('/last-responses', async (req, res) => {
  const { token, plate } = req.query;
  if (!token || !plate)
    return res.status(400).json({ error: 'Faltan parámetros token y plate.' });

  const { rows } = await pool.query(
    `SELECT c.id FROM clientes c
     JOIN units u ON u.cliente_id = c.id
     WHERE c.token = $1 AND c.enabled = true AND UPPER(u.plate) = UPPER($2)
     LIMIT 1`,
    [token, plate]
  );
  if (!rows.length)
    return res.status(403).json({ error: 'Patente no autorizada para este token.' });

  try {
    if (GPS_SOURCE === 'fly') {
      const data = await getFromFly('last-responses', plate);
      if (!data) return res.status(502).json({ error: 'El servidor GPS no devolvió datos.' });
      return res.json(data);
    }
    res.json(await getLastResponsesLocal(plate));
  } catch (e) {
    console.error('[gps-proxy/last-responses] error:', e.message);
    res.status(502).json({ error: 'Error consultando historial GPS.' });
  }
});

module.exports = router;
