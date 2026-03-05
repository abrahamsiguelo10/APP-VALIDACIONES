/**
 * routes/roles.js
 * GET    /roles         — listar todos los roles custom
 * POST   /roles         — crear rol (admin)
 * PATCH  /roles/:id     — editar label/modules (admin)
 * DELETE /roles/:id     — eliminar rol (admin)
 */

const router = require('express').Router();
const { query } = require('../db/pool');
const { requireAuth, requireRole } = require('../middleware/auth');
const audit = require('../middleware/audit');

router.use(requireAuth);

/* ── GET /roles ───────────────────────────────────────────────── */
router.get('/', async (req, res) => {
  const { rows } = await query(
    `SELECT id, label, modules, created_at, updated_at
     FROM public.roles ORDER BY created_at ASC`
  );
  res.json(rows);
});

/* ── POST /roles ──────────────────────────────────────────────── */
router.post('/', requireRole('admin'), async (req, res) => {
  const { id, label, modules = ['dashboard', 'validador'] } = req.body;

  if (!id || !label) {
    return res.status(400).json({ error: 'id y label son requeridos.' });
  }
  // No permitir pisar los roles fijos
  if (['admin', 'user'].includes(id.toLowerCase())) {
    return res.status(400).json({ error: 'No puedes usar "admin" o "user" como id de rol.' });
  }

  let rows;
  try {
    ({ rows } = await query(
      `INSERT INTO public.roles (id, label, modules)
       VALUES ($1, $2, $3)
       RETURNING *`,
      [id.trim().toLowerCase(), label.trim(), JSON.stringify(modules)]
    ));
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ error: `El rol "${id}" ya existe.` });
    }
    throw err;
  }

  await audit.log({ req, action: 'ROLE_CREATE', target: id, after: rows[0] });
  res.status(201).json(rows[0]);
});

/* ── PATCH /roles/:id ─────────────────────────────────────────── */
router.patch('/:id', requireRole('admin'), async (req, res) => {
  const { id } = req.params;
  const { label, modules } = req.body;

  const { rows: before } = await query(
    'SELECT * FROM public.roles WHERE id = $1', [id]
  );
  if (!before.length) return res.status(404).json({ error: 'Rol no encontrado.' });

  const updates = [];
  const values  = [];
  let   i       = 1;

  if (label   !== undefined) { updates.push(`label = $${i++}`);   values.push(label.trim()); }
  if (modules !== undefined) { updates.push(`modules = $${i++}`); values.push(JSON.stringify(modules)); }

  if (!updates.length) return res.status(400).json({ error: 'Nada que actualizar.' });

  updates.push(`updated_at = now()`);
  values.push(id);

  const { rows } = await query(
    `UPDATE public.roles SET ${updates.join(', ')}
     WHERE id = $${i} RETURNING *`,
    values
  );

  await audit.log({ req, action: 'ROLE_UPDATE', target: id, before: before[0], after: rows[0] });
  res.json(rows[0]);
});

/* ── DELETE /roles/:id ────────────────────────────────────────── */
router.delete('/:id', requireRole('admin'), async (req, res) => {
  // Verificar que no tenga usuarios asignados
  const { rows: users } = await query(
    'SELECT COUNT(*) FROM public.users WHERE role_id = $1', [req.params.id]
  );
  if (parseInt(users[0].count) > 0) {
    return res.status(409).json({
      error: 'No puedes eliminar un rol con usuarios asignados. Reasigna los usuarios primero.'
    });
  }

  const { rows } = await query(
    'DELETE FROM public.roles WHERE id = $1 RETURNING *', [req.params.id]
  );
  if (!rows.length) return res.status(404).json({ error: 'Rol no encontrado.' });

  await audit.log({ req, action: 'ROLE_DELETE', target: req.params.id });
  res.json({ ok: true });
});

module.exports = router;