// src/routes/destinations.js
const express = require('express');
const router  = express.Router();
const { query } = require('../db/pool');
const { requireAuth } = require('../middleware/auth');

// GET /destinations
router.get('/', requireAuth, async (req, res) => {
  try {
    const { rows } = await query(`
      SELECT id, name, enabled, api_url, color, field_schema,
             driver_slug, auth, created_at, updated_at
      FROM public.destinations
      ORDER BY name ASC
    `);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /destinations
router.post('/', requireAuth, async (req, res) => {
  const { id, name, api_url, color, field_schema, driver_slug, auth } = req.body;
  // Verificar si ya existe una org con el mismo nombre (insensible a mayúsculas)
const { rows: existing } = await pool.query(
  'SELECT id, name FROM public.destinations WHERE LOWER(name) = LOWER($1) LIMIT 1',
  [name]
);
if (existing.length) {
  return res.status(200).json(existing[0]); // devolver la existente sin crear duplicado
}
  if (!name) return res.status(400).json({ error: 'name es requerido' });
  try {
    const { rows } = await query(`
      INSERT INTO public.destinations
        (id, name, api_url, color, field_schema, driver_slug, auth, enabled)
      VALUES
        (COALESCE($1, gen_random_uuid()::text), $2, $3, $4, $5, $6, $7, true)
      RETURNING *
    `, [
      id        || null,
      name.trim(),
      api_url?.trim() || null,
      color     || '#38bdf8',
      JSON.stringify(field_schema || []),
      driver_slug?.trim() || null,
      auth ? JSON.stringify(auth) : null,
    ]);
    res.status(201).json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PATCH /destinations/:id
router.patch('/:id', requireAuth, async (req, res) => {
  const { id } = req.params;
  const { name, api_url, color, field_schema, driver_slug, auth } = req.body;

  const sets   = [];
  const values = [];
  let   i      = 1;

  if (name         !== undefined) { sets.push(`name = $${i++}`);         values.push(name.trim()); }
  if (api_url      !== undefined) { sets.push(`api_url = $${i++}`);      values.push(api_url?.trim() || null); }
  if (color        !== undefined) { sets.push(`color = $${i++}`);        values.push(color); }
  if (field_schema !== undefined) { sets.push(`field_schema = $${i++}`); values.push(JSON.stringify(field_schema)); }
  if (driver_slug  !== undefined) { sets.push(`driver_slug = $${i++}`);  values.push(driver_slug?.trim() || null); }
  if (auth         !== undefined) { sets.push(`auth = $${i++}`);         values.push(auth ? JSON.stringify(auth) : null); }

  if (!sets.length) return res.status(400).json({ error: 'Nada que actualizar.' });

  sets.push(`updated_at = now()`);
  values.push(id);

  try {
    const { rows } = await query(
      `UPDATE public.destinations SET ${sets.join(', ')} WHERE id = $${i} RETURNING *`,
      values
    );
    if (!rows.length) return res.status(404).json({ error: 'Destino no encontrado.' });
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PATCH /destinations/:id/toggle
router.patch('/:id/toggle', requireAuth, async (req, res) => {
  try {
    const { rows } = await query(`
      UPDATE public.destinations
        SET enabled = NOT enabled, updated_at = now()
      WHERE id = $1
      RETURNING *
    `, [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Destino no encontrado.' });
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /destinations/:id
router.delete('/:id', requireAuth, async (req, res) => {
  try {
    // Primero eliminar asignaciones para evitar FK error
    await query(
      'DELETE FROM public.unit_destinations WHERE destination_id = $1',
      [req.params.id]
    );
    const { rows } = await query(
      'DELETE FROM public.destinations WHERE id = $1 RETURNING id',
      [req.params.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Destino no encontrado.' });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
