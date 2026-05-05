'use strict';
/**
 * src/routes/public.js
 * Endpoints públicos — sin autenticación
 * IMPORTANTE: No consulta gps_events para evitar saturar el pool
 * Los datos GPS vienen del endpoint gps-proxy que tiene su propio caché
 */

const router    = require('express').Router();
const { query } = require('../db/pool');

console.log('[public] ruta cargada OK');

// GET /public/search?q=PATENTE_O_IMEI
router.get('/search', async (req, res) => {
  console.log('[public/search] q=', req.query.q);

  try {
    const q = (req.query.q || '').trim().toUpperCase().replace(/[^A-Z0-9]/g, '');
    if (!q || q.length < 4) {
      return res.status(400).json({ error: 'Mínimo 4 caracteres.' });
    }

    // 1. Unidad — solo tabla units + clientes (rápido, sin gps_events)
    const { rows: unitRows } = await query(`
      SELECT u.imei, u.plate, u.enabled, c.nombre AS cliente
      FROM public.units u
      LEFT JOIN public.clientes c ON c.id = u.cliente_id
      WHERE u.plate = $1 OR u.imei = $1
      LIMIT 1
    `, [q]);

    if (!unitRows.length) {
      return res.status(404).json({ error: 'Unidad no encontrada.' });
    }
    const unit = unitRows[0];

    // 2. Destinos — tabla unit_destinations + destinations (rápido)
    const { rows: destRows } = await query(`
      SELECT d.name AS nombre, ud.enabled
      FROM public.unit_destinations ud
      JOIN public.destinations d ON d.id = ud.destination_id
      WHERE ud.imei = $1
      ORDER BY d.name
    `, [unit.imei]);

    // Responder sin datos GPS — el frontend los puede obtener por separado
    // o mostramos lo que ya tenemos sin bloquear el pool con gps_events
    res.json({
      unit: {
        plate:   unit.plate,
        imei:    unit.imei,
        enabled: unit.enabled,
        cliente: unit.cliente || null,
      },
      gps:          null,   // se carga aparte vía /gps/unit-status
      destinations: destRows,
      history:      [],
    });

  } catch (err) {
    console.error('[public/search] error:', err.message);
    res.status(500).json({ error: 'Error interno.' });
  }
});

module.exports = router;
