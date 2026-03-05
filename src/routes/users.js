/**
 * routes/users.js
 * GET    /users
 * POST   /users
 * PATCH  /users/:id
 * PATCH  /users/:id/toggle
 * DELETE /users/:id
 *
 * Todos requieren auth + rol admin.
 */

const router  = require('express').Router();
const bcrypt  = require('bcrypt');
const { query } = require('../db/pool');
const { requireAuth, requireRole } = require('../middleware/auth');
const audit   = require('../middleware/audit');

const SALT_ROUNDS = 12;

router.use(requireAuth, requireRole('admin'));

/* ── GET /users ───────────────────────────────────────────────── */
router.get('/', async (req, res) => {
  const { rows } = await query(
    `SELECT id, username, role, enabled, created_at, updated_at
     FROM public.users
     ORDER BY id ASC`
  );
  res.json(rows);
});

/* ── POST /users ──────────────────────────────────────────────── */
router.post('/', async (req, res) => {
  const { username, password, role = 'user' } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'username y password son requeridos.' });
  }
  if (!['admin', 'user'].includes(role)) {
    return res.status(400).json({ error: 'Rol inválido. Usa "admin" o "user".' });
  }
  if (password.length < 4) {
    return res.status(400).json({ error: 'La contraseña debe tener al menos 4 caracteres.' });
  }

  const hash = await bcrypt.hash(password, SALT_ROUNDS);

  let rows;
  try {
    ({ rows } = await query(
      `INSERT INTO public.users (username, password_hash, role)
       VALUES ($1, $2, $3)
       RETURNING id, username, role, enabled, created_at`,
      [username.trim().toLowerCase(), hash, role]
    ));
  } catch (err) {
    if (err.code === '23505') { // unique_violation
      return res.status(409).json({ error: `El usuario "${username}" ya existe.` });
    }
    throw err;
  }

  await audit.log({ req, action: 'USER_CREATE', target: username, after: rows[0] });
  res.status(201).json(rows[0]);
});

/* ── PATCH /users/:id ─────────────────────────────────────────── */
router.patch('/:id', async (req, res) => {
  const id = parseInt(req.params.id);
  const { role, password } = req.body;

  // Obtener estado actual para audit
  const { rows: before } = await query(
    'SELECT id, username, role, enabled FROM public.users WHERE id = $1',
    [id]
  );
  if (!before.length) return res.status(404).json({ error: 'Usuario no encontrado.' });

  const updates = [];
  const values  = [];
  let   i       = 1;

  if (role !== undefined) {
    if (!['admin', 'user'].includes(role)) {
      return res.status(400).json({ error: 'Rol inválido.' });
    }
    updates.push(`role = $${i++}`);
    values.push(role);
  }

  if (password) {
    if (password.length < 4) {
      return res.status(400).json({ error: 'La contraseña debe tener al menos 4 caracteres.' });
    }
    const hash = await bcrypt.hash(password, SALT_ROUNDS);
    updates.push(`password_hash = $${i++}`);
    values.push(hash);
  }

  if (!updates.length) {
    return res.status(400).json({ error: 'Nada que actualizar.' });
  }

  updates.push(`updated_at = now()`);
  values.push(id);

  const { rows } = await query(
    `UPDATE public.users SET ${updates.join(', ')}
     WHERE id = $${i}
     RETURNING id, username, role, enabled, updated_at`,
    values
  );

  await audit.log({ req, action: 'USER_UPDATE', target: before[0].username, before: before[0], after: rows[0] });
  res.json(rows[0]);
});

/* ── PATCH /users/:id/toggle ─────────────────────────────────── */
router.patch('/:id/toggle', async (req, res) => {
  const id = parseInt(req.params.id);

  // No puede deshabilitarse a sí mismo
  if (id === req.user.id) {
    return res.status(400).json({ error: 'No puedes deshabilitarte a ti mismo.' });
  }

  const { rows } = await query(
    `UPDATE public.users
     SET enabled = NOT enabled, updated_at = now()
     WHERE id = $1
     RETURNING id, username, role, enabled`,
    [id]
  );
  if (!rows.length) return res.status(404).json({ error: 'Usuario no encontrado.' });

  const action = rows[0].enabled ? 'USER_ENABLE' : 'USER_DISABLE';
  await audit.log({ req, action, target: rows[0].username, after: rows[0] });
  res.json(rows[0]);
});

/* ── DELETE /users/:id ────────────────────────────────────────── */
router.delete('/:id', async (req, res) => {
  const id = parseInt(req.params.id);

  if (id === req.user.id) {
    return res.status(400).json({ error: 'No puedes eliminarte a ti mismo.' });
  }

  const { rows } = await query(
    'DELETE FROM public.users WHERE id = $1 RETURNING username',
    [id]
  );
  if (!rows.length) return res.status(404).json({ error: 'Usuario no encontrado.' });

  await audit.log({ req, action: 'USER_DELETE', target: rows[0].username });
  res.json({ ok: true, deleted: rows[0].username });
});

module.exports = router;
