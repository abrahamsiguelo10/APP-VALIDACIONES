'use strict';

/**
 * src/routes/gps-proxy.js
 */

const express    = require('express');
const { pool }   = require('../db/pool');

const router = express.Router();

const GPS_SOURCE        = process.env.GPS_SOURCE || 'local';
const GPS_FLY           = process.env.GPS_FLY_URL || 'https://integraciones-siguelogps-v2.fly.dev';
const HISTORY_LIMIT     = parseInt(process.env.GPS_HISTORY_LIMIT     || '50', 10);
const TX_ACTIVE_MINUTES = parseInt(process.env.GPS_TX_ACTIVE_MINUTES || '15', 10);

console.log(`[gps-proxy] Modo: ${GPS_SOURCE.toUpperCase()}`);

// ── Local: estado de transmisión ──────────────────────────────────

async function getUnitStatusLocal(plate) {
  // Último evento TCP
  const { rows } = await pool.query(
    `SELECT
       e.received_at,
       e.wialon_ts,
       EXTRACT(EPOCH FROM (now() - e.received_at)) / 60 AS age_minutes,
       u.imei
     FROM public.gps_events e
     JOIN public.units u ON UPPER(u.plate) = UPPER(e.plate)
     WHERE UPPER(e.plate) = UPPER($1)
     ORDER BY e.received_at DESC
     LIMIT 1`,
    [plate]
  );

  // Nombres de destinos asignados (tabla unit_destinations)
  const { rows: dRows } = await pool.query(
    `SELECT d.name
     FROM public.unit_destinations ud
     JOIN public.units u ON u.imei = ud.imei
     JOIN public.destinations d ON d.id = ud.destination_id
     WHERE UPPER(u.plate) = UPPER($1)
     ORDER BY d.name`,
    [plate]
  ).catch(() => ({ rows: [] }));

  const targets = dRows.map(r => r.name);

  if (!rows.length) {
    // Sin eventos TCP — buscar imei igual
    const { rows: uRows } = await pool.query(
      `SELECT imei FROM public.units WHERE UPPER(plate) = UPPER($1) LIMIT 1`,
      [plate]
    ).catch(() => ({ rows: [] }));
    return {
      isTransmitting:      false,
      tcpLastAt:           null,
      tcpAgeMinutes:       null,
      activeWindowMinutes: TX_ACTIVE_MINUTES,
      imei:                uRows[0]?.imei || null,
      targets,
    };
  }

  const r      = rows[0];
  const ageMin = parseFloat(r.age_minutes);
  return {
    isTransmitting:      ageMin <= TX_ACTIVE_MINUTES,
    tcpLastAt:           r.received_at,
    tcpAgeMinutes:       parseFloat(ageMin.toFixed(1)),
    activeWindowMinutes: TX_ACTIVE_MINUTES,
    imei:                r.imei || null,
    targets,
  };
}

// ── Local: historial de eventos ───────────────────────────────────

async function getLastResponsesLocal(plate) {
  const { rows } = await pool.query(
    `SELECT
       e.id,
       e.plate,
       e.lat,
       e.lon,
       e.speed,
       e.heading,
       e.ignition,
       e.wialon_ts,
       e.received_at,
       e.destination_id,
       d.name          AS destination_name,
       e.forward_ok    AS ok,
       e.forward_resp  AS response
     FROM public.gps_events e
     LEFT JOIN public.destinations d ON d.id::text = e.destination_id
     WHERE UPPER(e.plate) = UPPER($1)
     ORDER BY e.received_at DESC
     LIMIT $2`,
    [plate, HISTORY_LIMIT]
  );

  // Destinos asignados (para semáforo aunque no haya forwards aún)
  const { rows: assignedDests } = await pool.query(
    `SELECT d.id::text AS id, d.name
     FROM public.destinations d
     WHERE d.enabled = true
       AND EXISTS (
         SELECT 1 FROM public.units u
         WHERE UPPER(u.plate) = UPPER($1)
           AND u.destinations @> jsonb_build_array(
                 jsonb_build_object('destination_id', d.id::text)
               )
       )`,
    [plate]
  ).catch(() => ({ rows: [] }));

  const results = rows.map(r => ({
    at:             r.received_at,
    destination_id: r.destination_id || null,
    target:         r.destination_name || r.destination_id || null,
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

  // Si hay destinos asignados sin eventos propios, agregar entrada sintética
  if (assignedDests.length > 0) {
    const targetsInResults = new Set(results.map(r => r.target).filter(Boolean));
    for (const dest of assignedDests) {
      if (!targetsInResults.has(dest.name)) {
        const latestEvent = results[0] || null;
        results.push({
          at:             latestEvent ? latestEvent.at : null,
          destination_id: dest.id,
          target:         dest.name,
          ok:             null,
          response:       null,
          tx: latestEvent ? latestEvent.tx : {
            lat: null, lon: null, speed: null,
            heading: null, ignition: null, fechaHoraISO: null,
          },
        });
      }
    }
  }

  return { results };
}

// ── Helper: Fly legacy ────────────────────────────────────────────

async function getFromFly(endpoint, plate) {
  const url = `${GPS_FLY}/api/${endpoint}?plate=${encodeURIComponent(plate.toUpperCase())}`;
  try {
    const r = await fetch(url, { signal: AbortSignal.timeout(8000) });
    if (!r.ok) return null;
    return await r.json();
  } catch {
    return null;
  }
}

// ── Helper: verificar JWT admin ───────────────────────────────────

function verifyAdminJwt(token) {
  try {
    const jwt = require('jsonwebtoken');
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    return !!(payload && (payload.role === 'admin' || payload.username));
  } catch {
    return false;
  }
}

// ── Middleware admin (para /gps/admin) ────────────────────────────

function requireAdmin(req, res, next) {
  const authHeader = req.headers['authorization'] || '';
  const bearer = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (bearer && verifyAdminJwt(bearer)) return next();
  return res.status(401).json({ error: 'No autorizado.' });
}

// ── Autorizar por token cliente O JWT admin ───────────────────────

async function authorizeGps(req, plate) {
  const { token } = req.query;

  if (token) {
    const { rows } = await pool.query(
      `SELECT c.id FROM clientes c
       JOIN units u ON u.cliente_id = c.id
       WHERE c.token = $1 AND c.enabled = true AND UPPER(u.plate) = UPPER($2)
       LIMIT 1`,
      [token, plate]
    );
    if (!rows.length) {
      return { ok: false, status: 403, error: 'Patente no autorizada para este token.' };
    }
    return { ok: true };
  }

  const authHeader = req.headers['authorization'] || '';
  const bearer = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (bearer && verifyAdminJwt(bearer)) {
    return { ok: true };
  }

  return { ok: false, status: 400, error: 'Faltan parámetros token y plate.' };
}
// ── GET /gps/destino-eventos?plate=&dest_id=&limit= ──────────────────────────
// Historial de los últimos N envíos de una unidad a un destino específico.
// Protegido con requireAdmin (igual que /admin).
router.get('/destino-eventos', requireAdmin, async (req, res) => {
  const { plate, dest_id, limit = 8 } = req.query;
  if (!plate)    return res.status(400).json({ error: 'Falta plate.' });
  if (!dest_id)  return res.status(400).json({ error: 'Falta dest_id.' });
 
  try {
    const { rows } = await pool.query(`
      SELECT
        e.received_at   AS at,
        e.wialon_ts,
        e.lat, e.lon, e.speed, e.heading, e.ignition,
        e.forward_ok    AS ok,
        e.forward_resp  AS response
      FROM   public.gps_events e
      JOIN   public.units u ON u.imei = e.imei
      WHERE  UPPER(u.plate)     = UPPER($1)
        AND  e.destination_id::text = $2
      ORDER  BY e.received_at DESC
      LIMIT  $3
    `, [plate, dest_id, Math.min(parseInt(limit) || 8, 50)]);
 
    res.json(rows);
  } catch (e) {
    console.error('[gps-proxy/destino-eventos] error:', e.message);
    res.status(500).json({ error: 'Error consultando historial de destino.' });
  }
});

// ── GET /gps/admin?plate=XXX  (solo admin JWT) ────────────────────

router.get('/admin', requireAdmin, async (req, res) => {
  const { plate } = req.query;
  if (!plate) return res.status(400).json({ error: 'Falta plate.' });

  try {
    if (GPS_SOURCE === 'fly') {
      const [status, responses] = await Promise.all([
        getFromFly('unit-status',    plate),
        getFromFly('last-responses', plate),
      ]);
      return res.json({ status, responses });
    }
    const [status, responses] = await Promise.all([
      getUnitStatusLocal(plate),
      getLastResponsesLocal(plate),
    ]);
    res.json({ status, responses });
  } catch (e) {
    console.error('[gps-proxy/admin] error:', e.message);
    res.status(502).json({ error: 'Error consultando GPS.' });
  }
});

// ── GET /gps/unit-status?plate=yyy ───────────────────────────────

router.get('/unit-status', async (req, res) => {
  const { plate } = req.query;
  if (!plate) return res.status(400).json({ error: 'Falta plate.' });

  const auth = await authorizeGps(req, plate)
    .catch(e => ({ ok: false, status: 500, error: e.message }));
  if (!auth.ok) return res.status(auth.status).json({ error: auth.error });

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

// ── GET /gps/last-responses?plate=yyy ────────────────────────────

router.get('/last-responses', async (req, res) => {
  const { plate } = req.query;
  if (!plate) return res.status(400).json({ error: 'Falta plate.' });

  const auth = await authorizeGps(req, plate)
    .catch(e => ({ ok: false, status: 500, error: e.message }));
  if (!auth.ok) return res.status(auth.status).json({ error: auth.error });

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
