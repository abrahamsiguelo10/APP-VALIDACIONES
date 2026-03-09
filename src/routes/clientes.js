/**
 * routes/clientes.js
 * GET    /clientes          — listar clientes (admin)
 * GET    /clientes/:id      — detalle cliente (admin)
 * POST   /clientes          — crear cliente (admin)
 * PATCH  /clientes/:id      — editar cliente (admin)
 * DELETE /clientes/:id      — eliminar cliente (admin)
 * POST   /clientes/:id/regen-token — regenerar token (admin)
 *
 * GET    /clientes/validate?token=xxx — validar token (público)
 */

const router     = require('express').Router();
const { query }  = require('../db/pool');
const { requireAuth, requireRole } = require('../middleware/auth');
const audit      = require('../middleware/audit');
const crypto     = require('crypto');

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

/* ── Validar token (público, sin auth) ───────────────────────── */
router.get('/validate', async (req, res) => {
  const { token } = req.query;
  if (!token) return res.status(400).json({ error: 'token requerido.' });

  const { rows } = await query(
    `SELECT id, nombre, rut, enabled FROM public.clientes WHERE token = $1`,
    [token]
  );

  if (!rows.length) return res.status(404).json({ error: 'Token inválido.' });
  if (!rows[0].enabled) return res.status(403).json({ error: 'Cliente deshabilitado.' });

  res.json(rows[0]);
});

/* ── Todas las rutas siguientes requieren auth ───────────────── */
router.use(requireAuth);

/* ── GET /clientes ────────────────────────────────────────────── */
router.get('/', requireRole('admin'), async (_req, res) => {
  const { rows } = await query(`
    SELECT
      c.id, c.nombre, c.rut, c.token, c.enabled, c.created_at, c.updated_at,
      COUNT(u.imei)::int AS total_units
    FROM public.clientes c
    LEFT JOIN public.units u ON u.cliente_id = c.id
    GROUP BY c.id
    ORDER BY c.created_at DESC
  `);
  res.json(rows);
});

/* ── GET /clientes/:id ────────────────────────────────────────── */
router.get('/:id', requireRole('admin'), async (req, res) => {
  const { rows } = await query(
    `SELECT id, nombre, rut, token, enabled, created_at, updated_at
     FROM public.clientes WHERE id = $1`,
    [req.params.id]
  );
  if (!rows.length) return res.status(404).json({ error: 'Cliente no encontrado.' });
  res.json(rows[0]);
});

/* ── POST /clientes ───────────────────────────────────────────── */
router.post('/', requireRole('admin'), async (req, res) => {
  const { nombre, rut } = req.body;
  if (!nombre) return res.status(400).json({ error: 'nombre es requerido.' });

  const id    = crypto.randomUUID();
  const token = generateToken();

  const { rows } = await query(
    `INSERT INTO public.clientes (id, nombre, rut, token)
     VALUES ($1, $2, $3, $4)
     RETURNING id, nombre, rut, token, enabled, created_at`,
    [id, nombre.trim(), rut?.trim() || null, token]
  );

  await audit.log({ req, action: 'CLIENTE_CREATE', target: id, after: rows[0] });
  res.status(201).json(rows[0]);
});

/* ── PATCH /clientes/:id ──────────────────────────────────────── */
router.patch('/:id', requireRole('admin'), async (req, res) => {
  const { id } = req.params;
  const { nombre, rut, enabled } = req.body;

  const { rows: before } = await query(
    'SELECT * FROM public.clientes WHERE id = $1', [id]
  );
  if (!before.length) return res.status(404).json({ error: 'Cliente no encontrado.' });

  const updates = [];
  const values  = [];
  let   i       = 1;

  if (nombre  !== undefined) { updates.push(`nombre  = $${i++}`); values.push(nombre.trim()); }
  if (rut     !== undefined) { updates.push(`rut     = $${i++}`); values.push(rut?.trim() || null); }
  if (enabled !== undefined) { updates.push(`enabled = $${i++}`); values.push(enabled); }
  if (!updates.length) return res.status(400).json({ error: 'Nada que actualizar.' });

  updates.push(`updated_at = now()`);
  values.push(id);

  const { rows } = await query(
    `UPDATE public.clientes SET ${updates.join(', ')}
     WHERE id = $${i} RETURNING id, nombre, rut, token, enabled, updated_at`,
    values
  );

  await audit.log({ req, action: 'CLIENTE_UPDATE', target: id, before: before[0], after: rows[0] });
  res.json(rows[0]);
});

/* ── DELETE /clientes/:id ─────────────────────────────────────── */
router.delete('/:id', requireRole('admin'), async (req, res) => {
  const { rows } = await query(
    `DELETE FROM public.clientes WHERE id = $1 RETURNING id, nombre`,
    [req.params.id]
  );
  if (!rows.length) return res.status(404).json({ error: 'Cliente no encontrado.' });

  await audit.log({ req, action: 'CLIENTE_DELETE', target: req.params.id, before: rows[0] });
  res.json({ ok: true, deleted: rows[0] });
});

/* ── POST /clientes/:id/regen-token ──────────────────────────── */
router.post('/:id/regen-token', requireRole('admin'), async (req, res) => {
  const newToken = generateToken();

  const { rows } = await query(
    `UPDATE public.clientes SET token = $1, updated_at = now()
     WHERE id = $2 RETURNING id, nombre, token`,
    [newToken, req.params.id]
  );
  if (!rows.length) return res.status(404).json({ error: 'Cliente no encontrado.' });

  await audit.log({ req, action: 'CLIENTE_REGEN_TOKEN', target: req.params.id });
  res.json(rows[0]);
});

module.exports = router;
