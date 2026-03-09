// routes/gps-proxy.js
// Proxía las llamadas a la API GPS de Skynav/integraciones para evitar CORS en el cliente.
// Solo acepta peticiones autenticadas con token de cliente válido.

const express = require('express');
const { pool } = require('../db/pool');

const router = express.Router();

const GPS_BASE = 'https://integraciones-siguelogps-v2.fly.dev';

// GET /gps/unit-status?token=xxx&plate=yyy
// GET /gps/last-responses?token=xxx&plate=yyy
router.get('/:endpoint', async (req, res) => {
  const { endpoint } = req.params;
  const { token, plate } = req.query;

  if (!['unit-status', 'last-responses'].includes(endpoint)) {
    return res.status(404).json({ error: 'Endpoint no válido.' });
  }
  if (!token || !plate) {
    return res.status(400).json({ error: 'Faltan parámetros token y plate.' });
  }

  // Verificar que el token es válido y que la patente pertenece al cliente
  const clienteRes = await pool.query(
    `SELECT c.id FROM clientes c
     JOIN units u ON u.cliente_id = c.id
     WHERE c.token = $1 AND c.enabled = true AND UPPER(u.plate) = UPPER($2)
     LIMIT 1`,
    [token, plate]
  );
  if (clienteRes.rows.length === 0) {
    return res.status(403).json({ error: 'Patente no autorizada para este token.' });
  }

  // Proxiar a la API GPS
  try {
    const url = `${GPS_BASE}/api/${endpoint}?plate=${encodeURIComponent(plate.toUpperCase())}`;
    const gpsRes = await fetch(url, { headers: { 'Accept': 'application/json' } });
    const data = await gpsRes.json();
    res.status(gpsRes.status).json(data);
  } catch (e) {
    console.error('[gps-proxy] error:', e.message);
    res.status(502).json({ error: 'No se pudo contactar el servidor GPS.' });
  }
});

module.exports = router;
