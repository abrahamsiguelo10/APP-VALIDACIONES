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

// GET /gps/admin?plate=yyy  — uso interno admin (requiere JWT)
router.get('/admin', async (req, res) => {
  // Verificar JWT de admin/operador
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) return res.status(401).json({ error: 'No autorizado.' });
  const jwt = require('jsonwebtoken');
  let payload;
  try { payload = jwt.verify(auth.slice(7), process.env.JWT_SECRET); }
  catch { return res.status(401).json({ error: 'Sesión expirada.' }); }
  if (!['admin','operador'].includes(payload.role))
    return res.status(403).json({ error: 'Sin permisos.' });

  const { plate } = req.query;
  if (!plate) return res.status(400).json({ error: 'Falta plate.' });

  try {
    const [statusRes, responsesRes] = await Promise.all([
      fetch(`${GPS_BASE}/api/unit-status?plate=${encodeURIComponent(plate.toUpperCase())}`, { headers: { Accept: 'application/json' } }),
      fetch(`${GPS_BASE}/api/last-responses?plate=${encodeURIComponent(plate.toUpperCase())}`, { headers: { Accept: 'application/json' } }),
    ]);
    const status    = await statusRes.json();
    const responses = await responsesRes.json();
    res.json({ status, responses });
  } catch (e) {
    console.error('[gps-proxy/admin] error:', e.message);
    res.status(502).json({ error: 'No se pudo contactar el servidor GPS.' });
  }
});

module.exports = router;
