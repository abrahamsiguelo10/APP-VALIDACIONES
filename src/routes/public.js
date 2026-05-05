// src/routes/public.js
// Endpoints públicos — sin autenticación
// Solo devuelve datos no sensibles para el validador público

const router = require('express').Router();
const { query } = require('../db/pool');

// GET /public/search?q=PATENTE_O_IMEI
router.get('/search', async (req, res) => {
  const q = (req.query.q || '').trim().toUpperCase();
  if (!q || q.length < 4) return res.status(400).json({ error: 'Búsqueda muy corta.' });

  // Buscar unidad por patente o IMEI
  const { rows } = await query(`
    SELECT
      u.imei, u.plate, u.enabled,
      c.nombre AS cliente,
      COALESCE(
        json_agg(
          json_build_object('nombre', d.name, 'enabled', ud.enabled)
        ) FILTER (WHERE d.id IS NOT NULL),
        '[]'
      ) AS destinations
    FROM public.units u
    LEFT JOIN public.clientes c ON c.id = u.cliente_id
    LEFT JOIN public.unit_destinations ud ON ud.imei = u.imei
    LEFT JOIN public.destinations d ON d.id = ud.destination_id
    WHERE u.plate ILIKE $1 OR u.imei = $1
    GROUP BY u.imei, u.plate, u.enabled, c.nombre
    LIMIT 1
  `, [q]);

  if (!rows.length) return res.status(404).json({ error: 'Unidad no encontrada.' });
  const unit = rows[0];

  // Último evento GPS
  const { rows: gpsRows } = await query(`
    SELECT lat, lon, speed, heading, ignition, wialon_ts AS last_event, received_at
    FROM public.gps_events
    WHERE imei = $1
    ORDER BY received_at DESC
    LIMIT 1
  `, [unit.imei]);

  const gps = gpsRows[0] || {};

  // Últimos 10 envíos — solo destino, ok, fecha (sin payload ni respuesta detallada)
  const { rows: histRows } = await query(`
    SELECT
      ge.received_at AS fecha,
      d.name AS destino_nombre,
      ge.forward_ok AS ok,
      ge.speed AS velocidad_kmh,
      ge.ignition AS ignicion
    FROM public.gps_events ge
    LEFT JOIN public.destinations d ON d.id = ge.destination_id
    WHERE ge.imei = $1
      AND ge.destination_id IS NOT NULL
      AND ge.forward_ok IS NOT NULL
    ORDER BY ge.received_at DESC
    LIMIT 10
  `, [unit.imei]);

  res.json({
    unit: {
      plate:   unit.plate,
      imei:    unit.imei,
      enabled: unit.enabled,
      cliente: unit.cliente,
    },
    gps: {
      lat:          gps.lat       || null,
      lon:          gps.lon       || null,
      speed:        gps.speed     ?? null,
      ignition:     gps.ignition  ?? null,
      last_event:   gps.last_event || null,
      transmitting: gps.last_event
        ? (Date.now() - new Date(gps.last_event).getTime()) < 10 * 60 * 1000
        : false,
    },
    destinations: unit.destinations,
    history:      histRows,
  });
});

module.exports = router;
