'use strict';
/**
 * src/routes/public.js
 * Endpoints públicos — sin autenticación
 */

const router    = require('express').Router();
const { query } = require('../db/pool');

// Importar caché GPS del tcp-server (en memoria, sin tocar DB)
let _getLastGpsState = null;
try {
  const tcpServer = require('../tcp-server');
  _getLastGpsState = tcpServer.getLastGpsState;
  console.log('[public] caché GPS del tcp-server disponible');
} catch (e) {
  console.warn('[public] tcp-server no disponible, GPS se omitirá:', e.message);
}

console.log('[public] ruta cargada OK');

// GET /public/search?q=PATENTE_O_IMEI
router.get('/search', async (req, res) => {
  console.log('[public/search] q=', req.query.q);

  try {
    const q = (req.query.q || '').trim().toUpperCase().replace(/[^A-Z0-9-]/g, '');
    if (!q || q.length < 4) {
      return res.status(400).json({ error: 'Mínimo 4 caracteres.' });
    }

    // 1. Unidad
    // Buscar con match exacto Y sin guiones (para patentes como RDCR-56 o RDCR56)
    const qClean = q.replace(/-/g, ''); // versión sin guión
    const { rows: unitRows } = await query(`
      SELECT u.imei, u.plate, u.enabled, c.nombre AS cliente
      FROM public.units u
      LEFT JOIN public.clientes c ON c.id = u.cliente_id
      WHERE u.plate = $1
         OR u.plate = $2
         OR u.imei  = $1
         OR REPLACE(u.plate, '-', '') = $2
      LIMIT 1
    `, [q, qClean]);

    if (!unitRows.length) {
      return res.status(404).json({ error: 'Unidad no encontrada.' });
    }
    const unit = unitRows[0];

    // 2. Destinos
    const { rows: destRows } = await query(`
      SELECT d.name AS nombre, ud.enabled
      FROM public.unit_destinations ud
      JOIN public.destinations d ON d.id = ud.destination_id
      WHERE ud.imei = $1
      ORDER BY d.name
    `, [unit.imei]);

    // 3. GPS desde caché en memoria del tcp-server (sin tocar DB)
    let gps = null;
    if (_getLastGpsState) {
      const cached = _getLastGpsState(unit.plate);
      if (cached) {
        const ageMins = (Date.now() - new Date(cached.received_at).getTime()) / 60000;
        gps = {
          lat:          Number(cached.lat),
          lon:          Number(cached.lon),
          speed:        Number(cached.speed    || 0),
          heading:      Number(cached.heading  || 0),
          ignition:     Boolean(cached.ignition),
          last_event:   cached.wialon_ts || cached.received_at,
          received_at:  cached.received_at,
          transmitting: ageMins < 20,
        };
      }
    }

    res.json({
      unit: {
        plate:   unit.plate,
        imei:    unit.imei,
        enabled: unit.enabled,
        cliente: unit.cliente || null,
      },
      gps,
      destinations: destRows,
      history:      [],
    });

  } catch (err) {
    console.error('[public/search] error:', err.message);
    res.status(500).json({ error: 'Error interno.' });
  }
});

module.exports = router;
