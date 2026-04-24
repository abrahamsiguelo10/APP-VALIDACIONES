/**
 * routes/clientes.js  (query GET /clientes optimizada)
 *
 * PROBLEMA: el JOIN de gps_events en GET /clientes cuelga la DB
 * si la tabla tiene muchos registros sin índice en imei.
 *
 * FIX: usar subqueries correlacionadas con LIMIT 1 en lugar de
 * LEFT JOIN + GROUP BY sobre toda gps_events.
 */

const router  = require('express').Router();
const { query } = require('../db/pool');
const { requireAuth, requireRole } = require('../middleware/auth');
const audit   = require('../middleware/audit');
const crypto  = require('crypto');
const bcrypt  = require('bcrypt');
const jwt     = require('jsonwebtoken');

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

/* ── POST /clientes/login (público) ──────────────────────────── */
router.post('/login', async (req, res) => {
  const { rut, password } = req.body;
  if (!rut || !password)
    return res.status(400).json({ error: 'RUT y contraseña requeridos.' });

  const { rows } = await query(
    `SELECT id, nombre, rut, token, enabled, password_hash
       FROM public.clientes
      WHERE REPLACE(REPLACE(rut, '.', ''), '-', '') =
            REPLACE(REPLACE($1,  '.', ''), '-', '')`,
    [rut.trim()]
  );
  const cliente = rows[0];
  if (!cliente)         return res.status(401).json({ error: 'RUT o contraseña incorrectos.' });
  if (!cliente.enabled) return res.status(403).json({ error: 'Cuenta deshabilitada. Contacta al administrador.' });
  if (!cliente.password_hash) return res.status(401).json({ error: 'Acceso no configurado. Contacta al administrador.' });

  const valid = await bcrypt.compare(password, cliente.password_hash);
  if (!valid) return res.status(401).json({ error: 'RUT o contraseña incorrectos.' });

  const token = jwt.sign(
    { sub: cliente.id, rut: cliente.rut, nombre: cliente.nombre, tipo: 'cliente' },
    process.env.JWT_SECRET,
    { expiresIn: '24h' }
  );
  res.json({ token, cliente: { id: cliente.id, nombre: cliente.nombre, rut: cliente.rut } });
});

/* ── GET /clientes/me/units (cliente autenticado) ─────────────── */
router.get('/me/units', async (req, res) => {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer '))
    return res.status(401).json({ error: 'No autorizado.' });

  let payload;
  try { payload = jwt.verify(auth.slice(7), process.env.JWT_SECRET); }
  catch { return res.status(401).json({ error: 'Sesión expirada.' }); }
  if (payload.tipo !== 'cliente')
    return res.status(403).json({ error: 'No autorizado.' });

  const { rows } = await query(
    `SELECT imei, plate, rut, created_at
       FROM public.units
      WHERE cliente_id = $1 AND enabled = true
      ORDER BY plate ASC`,
    [payload.sub]
  );
  const { rows: cRows } = await query(
    'SELECT token FROM public.clientes WHERE id = $1',
    [payload.sub]
  );
  res.json({ units: rows, gps_token: cRows[0]?.token });
});

/* ── GET /clientes/validate?token=xxx (público) ──────────────── */
router.get('/validate', async (req, res) => {
  const { token } = req.query;
  if (!token) return res.status(400).json({ error: 'token requerido.' });

  const { rows } = await query(
    `SELECT id, nombre, rut, enabled FROM public.clientes WHERE token = $1`,
    [token]
  );
  if (!rows.length)      return res.status(404).json({ error: 'Token inválido.' });
  if (!rows[0].enabled)  return res.status(403).json({ error: 'Cliente deshabilitado.' });
  res.json(rows[0]);
});

/* ── Todas las rutas siguientes requieren auth ───────────────── */
router.use(requireAuth);

/* ── GET /clientes ────────────────────────────────────────────── */
// FIX: evitar JOIN directo a gps_events (puede ser muy lenta).
// Se usa subquery sólo sobre units y unit_destinations, que son tablas pequeñas.
// Los datos de último evento se obtienen con subquery correlacionada limitada.
router.get('/', requireRole('admin'), async (_req, res) => {
  const { rows } = await query(`
    SELECT
      c.id,
      c.nombre,
      c.rut,
      c.token,
      c.enabled,
      c.created_at,
      c.updated_at,

      /* ── total unidades ── */
      (
        SELECT COUNT(*)::int
        FROM public.units u
        WHERE u.cliente_id = c.id
      ) AS total_units,

      /* ── total destinos activos únicos ── */
      (
        SELECT COUNT(DISTINCT ud.destination_id)::int
        FROM public.units u
        JOIN public.unit_destinations ud ON ud.imei = u.imei AND ud.enabled = true
        WHERE u.cliente_id = c.id
      ) AS total_destinations,

      /* ── último evento: subquery con índice por imei ── */
      (
        SELECT MAX(ge.received_at)
        FROM public.gps_events ge
        WHERE ge.imei IN (
          SELECT imei FROM public.units WHERE cliente_id = c.id
        )
      ) AS last_event_at,

      /* ── último reenvío exitoso ── */
      (
        SELECT MAX(ge.received_at)
        FROM public.gps_events ge
        WHERE ge.forward_ok = true
          AND ge.imei IN (
            SELECT imei FROM public.units WHERE cliente_id = c.id
          )
      ) AS last_forward_at

    FROM public.clientes c
    ORDER BY c.created_at DESC
  `);
  res.json(rows);
});

/* ── GET /clientes/:id/units ─────────────────────────────────── */
router.get('/:id/units', requireRole('admin'), async (req, res) => {
  const { rows: check } = await query(
    'SELECT id FROM public.clientes WHERE id = $1',
    [req.params.id]
  );
  if (!check.length) return res.status(404).json({ error: 'Cliente no encontrado.' });

  const { rows } = await query(`
    SELECT
      u.imei,
      u.plate,
      u.name,
      u.rut,
      u.enabled,
      u.created_at,

      /* ── destinos asignados ── */
      COALESCE(
        json_agg(
          json_build_object(
            'destination_id', ud.destination_id,
            'name',           d.name,
            'enabled',        ud.enabled,
            'shadow',         ud.shadow,
            'color',          d.color
          )
        ) FILTER (WHERE ud.destination_id IS NOT NULL),
        '[]'
      ) AS destinations,

      /* ── último evento recibido ── */
      (
        SELECT ge.received_at
        FROM public.gps_events ge
        WHERE ge.imei = u.imei
        ORDER BY ge.received_at DESC
        LIMIT 1
      ) AS last_event_at,

      /* ── última ignición ── */
      (
        SELECT ge.ignition
        FROM public.gps_events ge
        WHERE ge.imei = u.imei AND ge.ignition IS NOT NULL
        ORDER BY ge.received_at DESC
        LIMIT 1
      ) AS last_ignition,

      /* ── último reenvío exitoso ── */
      (
        SELECT ge.received_at
        FROM public.gps_events ge
        WHERE ge.imei = u.imei AND ge.forward_ok = true
        ORDER BY ge.received_at DESC
        LIMIT 1
      ) AS last_forward_at

    FROM public.units u
    LEFT JOIN public.unit_destinations ud ON ud.imei = u.imei
    LEFT JOIN public.destinations       d  ON d.id   = ud.destination_id

    WHERE u.cliente_id = $1

    GROUP BY u.imei
    ORDER BY u.plate ASC
  `, [req.params.id]);

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

  const { rows: before } = await query('SELECT * FROM public.clientes WHERE id = $1', [id]);
  if (!before.length) return res.status(404).json({ error: 'Cliente no encontrado.' });

  const updates = [], values = [];
  let i = 1;
  if (nombre  !== undefined) { updates.push(`nombre  = $${i++}`); values.push(nombre.trim()); }
  if (rut     !== undefined) { updates.push(`rut     = $${i++}`); values.push(rut?.trim() || null); }
  if (enabled !== undefined) { updates.push(`enabled = $${i++}`); values.push(enabled); }
  if (!updates.length) return res.status(400).json({ error: 'Nada que actualizar.' });

  updates.push(`updated_at = now()`);
  values.push(id);

  const { rows } = await query(
    `UPDATE public.clientes SET ${updates.join(', ')} WHERE id = $${i}
     RETURNING id, nombre, rut, token, enabled, updated_at`,
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

/* ── POST /clientes/:id/set-password ─────────────────────────── */
router.post('/:id/set-password', requireRole('admin'), async (req, res) => {
  const { password } = req.body;
  if (!password || password.length < 6)
    return res.status(400).json({ error: 'La contraseña debe tener al menos 6 caracteres.' });

  const hash = await bcrypt.hash(password, 10);
  const { rows } = await query(
    `UPDATE public.clientes SET password_hash = $1, updated_at = now()
     WHERE id = $2 RETURNING id, nombre`,
    [hash, req.params.id]
  );
  if (!rows.length) return res.status(404).json({ error: 'Cliente no encontrado.' });
  await audit.log({ req, action: 'CLIENTE_SET_PASSWORD', target: req.params.id });
  res.json({ ok: true, cliente: rows[0] });
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
