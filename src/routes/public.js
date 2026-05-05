'use strict';
/**
 * src/routes/public.js
 * Endpoints públicos — sin autenticación
 * Solo devuelve datos no sensibles para el validador público
 */

const router     = require('express').Router();
const { query }  = require('../db/pool');

// GET /public/search?q=PATENTE_O_IMEI
router.get('/search', async (req, res) => {
  try {
    const q = (req.query.q || '').trim().toUpperCase().replace(/[^A-Z0-9]/g, '');
    if (!q || q.length < 4) {
      return res.status(400).json({ error: 'Búsqueda muy corta (mínimo 4 caracteres).' });
    }

    // ── 1. Buscar unidad por patente o IMEI ───────────────────────
    const { rows: unitRows } = await query(`
      SELECT
        u.imei, u.plate, u.enabled, u.cliente_id,
        c.nombre AS cliente
      FROM public.units u
      LEFT JOIN public.clientes c ON c.id = u.cliente_id
      WHERE u.plate = $1 OR u.imei = $1
      LIMIT 1
    `, [q]);

    if (!unitRows.length) {
      return res.status(404).json({ error: 'Unidad no encontrada.' });
    }
    const unit = unitRows[0];

    // ── 2. Destinos asignados ──────────────────────────────────────
    const { rows: destRows } = await query(`
      SELECT d.name AS nombre, ud.enabled
      FROM public.unit_destinations ud
      JOIN public.destinations d ON d.id = ud.destination_id
      WHERE ud.imei = $1
      ORDER BY d.name
    `, [unit.imei]);

    // ── 3. Último evento GPS — usa índice idx_gps_events_imei_received ──
    const { rows: gpsRows } = await query(`
      SELECT lat, lon, speed, heading, ignition, wialon_ts AS last_event
      FROM public.gps_events
      WHERE imei = $1
      ORDER BY received_at DESC
      LIMIT 1
    `, [unit.imei]);

    const gps = gpsRows[0] || {};
    const lastEventMs = gps.last_event ? new Date(gps.last_event).getTime() : null;
    const transmitting = lastEventMs
      ? (Date.now() - lastEventMs) < 20 * 60 * 1000  // menos de 20 min
      : false;

    // ── 4. Historial últimos 10 envíos — solo con destination_id ──
    const { rows: histRows } = await query(`
      SELECT
        ge.received_at   AS fecha,
        d.name           AS destino_nombre,
        ge.forward_ok    AS ok,
        ge.speed         AS velocidad_kmh,
        ge.ignition      AS ignicion
      FROM public.gps_events ge
      LEFT JOIN public.destinations d ON d.id = ge.destination_id
      WHERE ge.imei = $1
        AND ge.destination_id IS NOT NULL
        AND ge.forward_ok IS NOT NULL
      ORDER BY ge.received_at DESC
      LIMIT 10
    `, [unit.imei]);

    // ── Respuesta ──────────────────────────────────────────────────
    res.json({
      unit: {
        plate:   unit.plate,
        imei:    unit.imei,
        enabled: unit.enabled,
        cliente: unit.cliente || null,
      },
      gps: {
        lat:          gps.lat        ? Number(gps.lat)   : null,
        lon:          gps.lon        ? Number(gps.lon)   : null,
        speed:        gps.speed      != null ? Number(gps.speed)   : null,
        heading:      gps.heading    != null ? Number(gps.heading) : null,
        ignition:     gps.ignition   ?? null,
        last_event:   gps.last_event || null,
        transmitting,
      },
      destinations: destRows,
      history:      histRows,
    });

  } catch (err) {
    console.error('[public/search] error:', err.message);
    res.status(500).json({ error: 'Error interno del servidor.' });
  }
});

module.exports = router;
