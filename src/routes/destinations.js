/**
 * routes/destinations.js
 * GET    /destinations
 * POST   /destinations
 * PATCH  /destinations/:id
 * PATCH  /destinations/:id/toggle
 * DELETE /destinations/:id
 *
 * Requieren auth. POST/PATCH/DELETE requieren rol admin.
 */

const router  = require('express').Router();
const { query } = require('../db/pool');
const { requireAuth, requireRole } = require('../middleware/auth');
const audit   = require('../middleware/audit');

router.use(requireAuth);

/* ── GET /destinations ────────────────────────────────────────── */
router.get('/', async (req, res) => {
  const { rows } = await query(
    `SELECT id, name, enabled, api_url, color, field_schema, created_at, updated_at
     FROM public.destinations
     ORDER BY name ASC`
  );
  res.json(rows);
});

/* ── POST /destinations ───────────────────────────────────────── */
router.post('/', requireRole('admin'), async (req, res) => {
  const { id, name, api_url, color, field_schema = [] } = req.body;

  if (!id || !name) {
    return res.status(400).json({ error: 'id y name son requeridos.' });
  }

  let rows;
  try {
    ({ rows } = await query(
      `INSERT INTO public.destinations (id, name, api_url, color, field_schema)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, name, enabled, api_url, color, field_schema, created_at`,
      [id.trim(), name.trim(), api_url || null, color || '#38bdf8', JSON.stringify(field_schema)]
    ));
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ error: `El destino con id "${id}" ya existe.` });
    }
    throw err;
  }

  await audit.log({ req, action: 'DEST_CREATE', target: id, after: rows[0] });
  res.status(201).json(rows[0]);
});

/* ── PATCH /destinations/:id ──────────────────────────────────── */
router.patch('/:id', requireRole('admin'), async (req, res) => {
  const { id } = req.params;
  const { name, api_url, color, field_schema } = req.body;

  const { rows: before } = await query(
    'SELECT * FROM public.destinations WHERE id = $1',
    [id]
  );
  if (!before.length) return res.status(404).json({ error: 'Destino no encontrado.' });

  const updates = [];
  const values  = [];
  let   i       = 1;

  if (name        !== undefined) { updates.push(`name = $${i++}`);         values.push(name.trim()); }
  if (api_url     !== undefined) { updates.push(`api_url = $${i++}`);      values.push(api_url || null); }
  if (color       !== undefined) { updates.push(`color = $${i++}`);        values.push(color); }
  if (field_schema !== undefined) { updates.push(`field_schema = $${i++}`); values.push(JSON.stringify(field_schema)); }

  if (!updates.length) return res.status(400).json({ error: 'Nada que actualizar.' });

  updates.push(`updated_at = now()`);
  values.push(id);

  const { rows } = await query(
    `UPDATE public.destinations SET ${updates.join(', ')}
     WHERE id = $${i}
     RETURNING id, name, enabled, api_url, color, field_schema, updated_at`,
    values
  );

  await audit.log({ req, action: 'DEST_UPDATE', target: id, before: before[0], after: rows[0] });
  res.json(rows[0]);
});

/* ── PATCH /destinations/:id/toggle ──────────────────────────── */
router.patch('/:id/toggle', requireRole('admin'), async (req, res) => {
  const { rows } = await query(
    `UPDATE public.destinations
     SET enabled = NOT enabled, updated_at = now()
     WHERE id = $1
     RETURNING id, name, enabled`,
    [req.params.id]
  );
  if (!rows.length) return res.status(404).json({ error: 'Destino no encontrado.' });

  const action = rows[0].enabled ? 'DEST_ENABLE' : 'DEST_DISABLE';
  await audit.log({ req, action, target: req.params.id, after: rows[0] });
  res.json(rows[0]);
});

/* ── DELETE /destinations/:id ─────────────────────────────────── */
router.delete('/:id', requireRole('admin'), async (req, res) => {
  const { rows } = await query(
    'DELETE FROM public.destinations WHERE id = $1 RETURNING id, name',
    [req.params.id]
  );
  if (!rows.length) return res.status(404).json({ error: 'Destino no encontrado.' });

  await audit.log({ req, action: 'DEST_DELETE', target: req.params.id, before: rows[0] });
  res.json({ ok: true, deleted: rows[0] });
});

module.exports = router;
