/**
 * routes/validador.js
 * Endpoint PÚBLICO para el validador de clientes.
 * No requiere JWT — usa token de cliente.
 *
 * GET /validador?token=xxx&plate=YYY
 * GET /validador?token=xxx&imei=YYY
 */

const router    = require('express').Router();
const { query } = require('../db/pool');

router.get('/', async (req, res) => {
  const { token, plate, imei } = req.query;

  if (!token) return res.status(400).json({ error: 'token requerido.' });
  if (!plate && !imei) return res.status(400).json({ error: 'plate o imei requerido.' });

  // 1. Validar token y obtener cliente
  const { rows: clienteRows } = await query(
    `SELECT id, nombre, rut, enabled FROM public.clientes WHERE token = $1`,
    [token]
  );

  if (!clienteRows.length) return res.status(404).json({ error: 'Token inválido.' });
  if (!clienteRows[0].enabled) return res.status(403).json({ error: 'Acceso deshabilitado.' });

  const cliente = clienteRows[0];

  // 2. Buscar unidad filtrando por cliente_id
  let sql = `
    SELECT
      u.imei, u.plate, u.name, u.rut, u.enabled, u.cliente_id,
      COALESCE(
        json_agg(
          json_build_object(
            'destination_id', ud.destination_id,
            'name',           d.name,
            'enabled',        ud.enabled,
            'color',          d.color
          )
        ) FILTER (WHERE ud.destination_id IS NOT NULL),
        '[]'
      ) AS destinations
    FROM public.units u
    LEFT JOIN public.unit_destinations ud ON ud.imei = u.imei
    LEFT JOIN public.destinations d       ON d.id    = ud.destination_id
    WHERE u.cliente_id = $1
  `;

  const values = [cliente.id];

  if (imei) {
    sql += ` AND u.imei = $2`;
    values.push(imei.trim());
  } else {
    sql += ` AND LOWER(u.plate) = LOWER($2)`;
    values.push(plate.trim());
  }

  sql += ` GROUP BY u.imei`;

  const { rows } = await query(sql, values);

  if (!rows.length) {
    return res.status(404).json({
      error: imei
        ? `IMEI ${imei} no encontrado para este cliente.`
        : `Patente ${plate} no encontrada para este cliente.`
    });
  }

  res.json({
    cliente: { nombre: cliente.nombre, rut: cliente.rut },
    unit: rows[0],
  });
});

module.exports = router;
