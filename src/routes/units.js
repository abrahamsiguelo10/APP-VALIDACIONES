/**
 * routes/units.js
 * GET    /units                          — listado con destinos
 * GET    /units/:imei                    — detalle de una unidad
 * POST   /units                          — crear unidad
 * PATCH  /units/:imei                    — editar unidad
 * PATCH  /units/:imei/toggle             — habilitar/deshabilitar
 * DELETE /units/:imei                    — eliminar
 *
 * GET    /units/:imei/destinations       — destinos asignados
 * POST   /units/:imei/destinations       — asignar destino
 * PATCH  /units/:imei/destinations/:did  — actualizar asignación
 * DELETE /units/:imei/destinations/:did  — quitar destino
 */

const router  = require('express').Router();
const { query } = require('../db/pool');
const { requireAuth, requireRole } = require('../middleware/auth');
const audit   = require('../middleware/audit');

router.use(requireAuth);

/* ══════════════════════════════════════════
   UNIDADES
══════════════════════════════════════════ */

/* ── GET /units ───────────────────────────────────────────────── */
router.get('/', async (req, res) => {
  const { search } = req.query;

  let sql = `
    SELECT
      u.imei, u.plate, u.name, u.rut, u.enabled, u.cliente_id,
      u.created_at, u.updated_at,
      COALESCE(
        json_agg(
          json_build_object(
            'destination_id', ud.destination_id,
            'name',           d.name,
            'enabled',        ud.enabled,
            'shadow',         ud.shadow,
            'notes',          ud.notes
          )
        ) FILTER (WHERE ud.destination_id IS NOT NULL),
        '[]'
      ) AS destinations
    FROM public.units u
    LEFT JOIN public.unit_destinations ud ON ud.imei = u.imei
    LEFT JOIN public.destinations d       ON d.id    = ud.destination_id
  `;

  const values = [];
  if (search) {
    sql += ` WHERE u.imei ILIKE $1 OR u.plate ILIKE $1 OR u.name ILIKE $1`;
    values.push(`%${search}%`);
  }

  sql += ` GROUP BY u.imei ORDER BY u.created_at DESC`;

  const { rows } = await query(sql, values);
  res.json(rows);
});

/* ── GET /units/:imei ─────────────────────────────────────────── */
router.get('/:imei', async (req, res) => {
  const { rows } = await query(
    `SELECT
       u.imei, u.plate, u.name, u.rut, u.enabled, u.cliente_id, u.created_at, u.updated_at,
       COALESCE(
         json_agg(
           json_build_object(
             'destination_id', ud.destination_id,
             'name',           d.name,
             'enabled',        ud.enabled,
             'shadow',         ud.shadow,
             'notes',          ud.notes
           )
         ) FILTER (WHERE ud.destination_id IS NOT NULL),
         '[]'
       ) AS destinations
     FROM public.units u
     LEFT JOIN public.unit_destinations ud ON ud.imei = u.imei
     LEFT JOIN public.destinations d       ON d.id    = ud.destination_id
     WHERE u.imei = $1
     GROUP BY u.imei`,
    [req.params.imei]
  );
  if (!rows.length) return res.status(404).json({ error: 'Unidad no encontrada.' });
  res.json(rows[0]);
});

/* ── POST /units ──────────────────────────────────────────────── */
router.post('/', requireRole('admin'), async (req, res) => {
  const { imei, plate, name, rut, cliente_id } = req.body;

  if (!imei) return res.status(400).json({ error: 'imei es requerido.' });

  let rows;
  try {
    ({ rows } = await query(
      `INSERT INTO public.units (imei, plate, name, rut, cliente_id)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING imei, plate, name, rut, enabled, cliente_id, created_at`,
      [imei.trim(), plate?.trim() || null, name?.trim() || null, rut || null, cliente_id || null]
    ));
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ error: `El IMEI "${imei}" ya existe.` });
    }
    throw err;
  }

  await audit.log({ req, action: 'UNIT_CREATE', target: imei, after: rows[0] });
  res.status(201).json(rows[0]);
});

/* ── POST /units/batch ────────────────────────────────────────── */
router.post('/batch', requireRole('admin'), async (req, res) => {
  const { units } = req.body;

  if (!Array.isArray(units) || !units.length)
    return res.status(400).json({ error: 'units debe ser un array no vacío.' });

  const chunk = units.slice(0, 1000);

  const valuePlaceholders = chunk.map((_, i) =>
    `($${i * 5 + 1}, $${i * 5 + 2}, $${i * 5 + 3}, $${i * 5 + 4}, $${i * 5 + 5})`
  ).join(', ');

  const params = chunk.flatMap(u => [
    String(u.imei).trim(),
    u.plate?.trim()  || null,
    u.name?.trim()   || null,
    u.rut            || null,
    u.cliente_id     || null,
  ]);

  await query(`
    INSERT INTO public.units (imei, plate, name, rut, cliente_id)
    VALUES ${valuePlaceholders}
    ON CONFLICT (imei) DO UPDATE SET
      plate      = EXCLUDED.plate,
      name       = EXCLUDED.name,
      rut        = EXCLUDED.rut,
      cliente_id = EXCLUDED.cliente_id,
      updated_at = now()
  `, params);

  await audit.log({ req, action: 'UNIT_BATCH_UPSERT', target: chunk.length + ' unidades' });
  res.json({ ok: true, count: chunk.length });
});

/* ── DELETE /units/batch ──────────────────────────────────────── */
router.delete('/batch', requireRole('admin'), async (req, res) => {
  const { imeis } = req.body;

  if (!Array.isArray(imeis) || !imeis.length)
    return res.status(400).json({ error: 'imeis debe ser un array no vacío.' });

  const placeholders = imeis.map((_, i) => `$${i + 1}`).join(', ');
  const { rows } = await query(
    `DELETE FROM public.units WHERE imei = ANY(ARRAY[${placeholders}]) RETURNING imei`,
    imeis
  );

  await audit.log({ req, action: 'UNIT_BATCH_DELETE', target: rows.length + ' unidades' });
  res.json({ ok: true, deleted: rows.length });
});

/* ── PATCH /units/:imei ───────────────────────────────────────── */
router.patch('/:imei', requireRole('admin'), async (req, res) => {
  const { imei } = req.params;
  const { plate, name, rut, cliente_id, enabled } = req.body;

  const { rows: before } = await query(
    'SELECT * FROM public.units WHERE imei = $1', [imei]
  );
  if (!before.length) return res.status(404).json({ error: 'Unidad no encontrada.' });

  const updates = [];
  const values  = [];
  let   i       = 1;
  
  if (plate      !== undefined) { updates.push(`plate      = $${i++}`); values.push(plate?.trim() || null); }
  if (name       !== undefined) { updates.push(`name       = $${i++}`); values.push(name?.trim()  || null); }
  if (rut        !== undefined) { updates.push(`rut        = $${i++}`); values.push(rut || null); }
  if (cliente_id !== undefined) { updates.push(`cliente_id = $${i++}`); values.push(cliente_id || null); }
  if (enabled    !== undefined) { updates.push(`enabled    = $${i++}`); values.push(enabled); }
  if (!updates.length) return res.status(400).json({ error: 'Nada que actualizar.' });

  updates.push(`updated_at = now()`);
  values.push(imei);

  const { rows } = await query(
    `UPDATE public.units SET ${updates.join(', ')}
     WHERE imei = $${i}
     RETURNING imei, plate, name, enabled, updated_at`,
    values
  );

  await audit.log({ req, action: 'UNIT_UPDATE', target: imei, before: before[0], after: rows[0] });
  res.json(rows[0]);
});

/* ── PATCH /units/:imei/toggle ────────────────────────────────── */
router.patch('/:imei/toggle', requireRole('admin'), async (req, res) => {
  const { rows } = await query(
    `UPDATE public.units SET enabled = NOT enabled, updated_at = now()
     WHERE imei = $1
     RETURNING imei, plate, name, enabled`,
    [req.params.imei]
  );
  if (!rows.length) return res.status(404).json({ error: 'Unidad no encontrada.' });

  await audit.log({ req, action: rows[0].enabled ? 'UNIT_ENABLE' : 'UNIT_DISABLE', target: req.params.imei });
  res.json(rows[0]);
});

/* ── DELETE /units/:imei ──────────────────────────────────────── */
router.delete('/:imei', requireRole('admin'), async (req, res) => {
  const { rows } = await query(
    'DELETE FROM public.units WHERE imei = $1 RETURNING imei, plate',
    [req.params.imei]
  );
  if (!rows.length) return res.status(404).json({ error: 'Unidad no encontrada.' });

  await audit.log({ req, action: 'UNIT_DELETE', target: req.params.imei, before: rows[0] });
  res.json({ ok: true, deleted: rows[0] });
});

/* ══════════════════════════════════════════
   DESTINOS DE UNA UNIDAD
══════════════════════════════════════════ */

/* ── GET /units/:imei/destinations ───────────────────────────── */
router.get('/:imei/destinations', async (req, res) => {
  const { rows } = await query(
    `SELECT ud.destination_id, d.name, d.api_url, d.color, d.field_schema,
            ud.enabled, ud.shadow, ud.notes, ud.created_at, ud.updated_at
     FROM public.unit_destinations ud
     JOIN public.destinations d ON d.id = ud.destination_id
     WHERE ud.imei = $1
     ORDER BY d.name`,
    [req.params.imei]
  );
  res.json(rows);
});

/* ── POST /units/:imei/destinations ──────────────────────────── */
router.post('/:imei/destinations', requireRole('admin'), async (req, res) => {
  const { imei } = req.params;
  const { destination_id, shadow = false, notes } = req.body;

  if (!destination_id) {
    return res.status(400).json({ error: 'destination_id es requerido.' });
  }

  let rows;
  try {
    ({ rows } = await query(
      `INSERT INTO public.unit_destinations (imei, destination_id, shadow, notes)
       VALUES ($1, $2, $3, $4)
       RETURNING *`,
      [imei, destination_id, shadow, notes || null]
    ));
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ error: 'Esta unidad ya tiene ese destino asignado.' });
    }
    throw err;
  }

  await audit.log({ req, action: 'UNIT_DEST_ADD', target: `${imei}→${destination_id}`, after: rows[0] });
  res.status(201).json(rows[0]);
});

/* ── PATCH /units/:imei/destinations/:did ────────────────────── */
router.patch('/:imei/destinations/:did', requireRole('admin'), async (req, res) => {
  const { imei, did } = req.params;
  const { enabled, shadow, notes } = req.body;

  const updates = [];
  const values  = [];
  let   i       = 1;

  if (enabled !== undefined) { updates.push(`enabled = $${i++}`); values.push(enabled); }
  if (shadow  !== undefined) { updates.push(`shadow  = $${i++}`); values.push(shadow); }
  if (notes   !== undefined) { updates.push(`notes   = $${i++}`); values.push(notes); }

  if (!updates.length) return res.status(400).json({ error: 'Nada que actualizar.' });

  updates.push(`updated_at = now()`);
  values.push(imei, did);

  const { rows } = await query(
    `UPDATE public.unit_destinations
     SET ${updates.join(', ')}
     WHERE imei = $${i} AND destination_id = $${i + 1}
     RETURNING *`,
    values
  );
  if (!rows.length) return res.status(404).json({ error: 'Asignación no encontrada.' });

  res.json(rows[0]);
});

/* ── DELETE /units/:imei/destinations/:did ───────────────────── */
router.delete('/:imei/destinations/:did', requireRole('admin'), async (req, res) => {
  const { imei, did } = req.params;
  const { rows } = await query(
    `DELETE FROM public.unit_destinations
     WHERE imei = $1 AND destination_id = $2
     RETURNING *`,
    [imei, did]
  );
  if (!rows.length) return res.status(404).json({ error: 'Asignación no encontrada.' });

  await audit.log({ req, action: 'UNIT_DEST_REMOVE', target: `${imei}→${did}` });
  res.json({ ok: true });
});

module.exports = router;
