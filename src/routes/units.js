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
 *
 * GET    /units/:imei/preview-payload    — payload simulado por destino (para validador)
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





router.post('/last-events', async (req, res) => {
  const { imeis } = req.body;
  if (!Array.isArray(imeis) || !imeis.length) return res.json([]);
 
  const safeImeis = imeis.slice(0, 1000);
  const placeholders = safeImeis.map((_, i) => `$${i + 1}`).join(', ');
 
  const { rows } = await query(`
    SELECT DISTINCT ON (ge.imei)
      ge.imei,
      ge.received_at AS last_event_at,
      ge.ignition    AS last_ignition
    FROM public.gps_events ge
    WHERE ge.imei IN (${placeholders})
    ORDER BY ge.imei, ge.received_at DESC
  `, safeImeis);
 
  res.json(rows);
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

/* ── PATCH /units/:imei/change-imei ────────────────────────────
   Cambia el IMEI de una unidad y actualiza TODAS las tablas relacionadas.
   Body: { new_imei: "nuevo_imei" }
   ────────────────────────────────────────────────────────────── */
router.patch('/:imei/change-imei', requireRole('admin'), async (req, res) => {
  const oldImei = req.params.imei;
  const { new_imei } = req.body;

  if (!new_imei || !new_imei.trim()) {
    return res.status(400).json({ error: 'new_imei es requerido.' });
  }

  const newImei = new_imei.trim();

  if (oldImei === newImei) {
    return res.status(400).json({ error: 'El IMEI nuevo es igual al actual.' });
  }

  const { rows: original } = await query(
    'SELECT * FROM public.units WHERE imei = $1', [oldImei]
  );
  if (!original.length) {
    return res.status(404).json({ error: 'Unidad no encontrada.' });
  }

  const { rows: existing } = await query(
    'SELECT imei FROM public.units WHERE imei = $1', [newImei]
  );
  if (existing.length) {
    return res.status(409).json({ error: `El IMEI "${newImei}" ya está en uso por otra unidad.` });
  }

  const client = await require('../db/pool').pool.connect();
  try {
    await client.query('BEGIN');

    await client.query(
      `INSERT INTO public.units (imei, plate, name, rut, enabled, cliente_id, created_at, updated_at)
       SELECT $1, plate, name, rut, enabled, cliente_id, created_at, now()
       FROM public.units WHERE imei = $2`,
      [newImei, oldImei]
    );

    await client.query(
      'UPDATE public.unit_destinations SET imei = $1 WHERE imei = $2',
      [newImei, oldImei]
    );

    await client.query(
      'UPDATE public.gps_events SET imei = $1 WHERE imei = $2',
      [newImei, oldImei]
    );

    await client.query(
      'DELETE FROM public.units WHERE imei = $1',
      [oldImei]
    );

    await client.query('COMMIT');

    await audit.log({
      req,
      action: 'UNIT_CHANGE_IMEI',
      target: `${oldImei} → ${newImei}`,
      before: { imei: oldImei },
      after:  { imei: newImei },
    });

    res.json({ ok: true, old_imei: oldImei, new_imei: newImei });

  } catch (err) {
    await client.query('ROLLBACK');
    console.error('[units] change-imei error:', err.message);
    res.status(500).json({ error: 'Error al cambiar IMEI: ' + err.message });
  } finally {
    client.release();
  }
});

/* ══════════════════════════════════════════
   PREVIEW PAYLOAD
══════════════════════════════════════════ */

/* ── GET /units/:imei/preview-payload ────────────────────────────
   Devuelve el payload exacto que el tcp-server construiría para cada
   destino activo de esta unidad, usando el último evento GPS disponible.
   Permite verificar qué valores fijos y dinámicos se están enviando.
   ────────────────────────────────────────────────────────────── */
router.get('/:imei/preview-payload', async (req, res) => {
  const { imei } = req.params;

  // Último evento GPS
  const { rows: eventRows } = await query(`
    SELECT lat, lon, speed, heading, ignition, alt, sats, hdop,
           odometro, wialon_ts, received_at
    FROM public.gps_events
    WHERE imei = $1
    ORDER BY received_at DESC
    LIMIT 1
  `, [imei]);

  const ev = eventRows[0] || {};

  // Datos de unidad + cliente
  const { rows: unitRows } = await query(`
    SELECT u.imei, u.plate, u.name, u.rut, u.cliente_id,
           c.nombre AS cliente_nombre, c.rut AS cliente_rut
    FROM public.units u
    LEFT JOIN public.clientes c ON c.id = u.cliente_id
    WHERE u.imei = $1
  `, [imei]);

  if (!unitRows.length) return res.status(404).json({ error: 'Unidad no encontrada.' });
  const unit = unitRows[0];

  // Destinos activos con field_schema
  const { rows: destRows } = await query(`
    SELECT d.id, d.name, d.api_url, d.field_schema, d.driver_slug,
           ud.shadow, ud.enabled
    FROM public.unit_destinations ud
    JOIN public.destinations d ON d.id = ud.destination_id
    WHERE ud.imei = $1
      AND ud.enabled = true
      AND d.enabled  = true
    ORDER BY d.name
  `, [imei]);

  // Resolver source → valor (misma lógica que tcp-server resolveSource)
  function resolveSource(source, fixedValue) {
    // Campos fixed: source === 'fixed' O source vacío pero con fixedValue
    if (
      source === 'fixed' ||
      ((!source || source === '') && fixedValue !== undefined && fixedValue !== null && fixedValue !== '')
    ) {
      return fixedValue;
    }

    const pad = n => String(n).padStart(2, '0');
    const iso  = ev.wialon_ts ? new Date(ev.wialon_ts).toISOString() : new Date().toISOString();
    const d    = new Date(iso);
    const chile = () => {
      try { return new Date(new Date(iso).toLocaleString('en-US', { timeZone: 'America/Santiago' })); }
      catch (_) { return new Date(d.getTime() - 3 * 3600 * 1000); }
    };

    switch (source) {
      case 'lat':                return ev.lat         ?? 0;
      case 'lon':                return ev.lon         ?? 0;
      case 'speed':              return ev.speed       ?? 0;
      case 'heading':            return ev.heading     ?? 0;
      case 'ignition':           return ev.ignition    ?? false;
      case 'ignition01':         return ev.ignition ? 1 : 0;
      case 'alt':                return ev.alt         ?? 0;
      case 'sats':               return ev.sats        ?? 0;
      case 'hdop':               return ev.hdop        ?? 0;
      case 'odometro':           return ev.odometro    ?? 0;
      case 'unit_plate':
      case 'plate':              return unit.plate     || '';
      case 'unit_imei':
      case 'imei':               return unit.imei      || '';
      case 'unit_name':          return unit.name      || '';
      case 'unit_rut':           return unit.rut       || '';
      case 'cliente_nombre':     return unit.cliente_nombre || unit.name || '';
      case 'cliente_rut':        return unit.cliente_rut    || unit.rut  || '';
      case 'cliente_rut_limpio': return (unit.cliente_rut || unit.rut || '').replace(/\./g,'').replace(/-/g,'').trim();
      case 'unit_rut_limpio':    return (unit.rut || '').replace(/\./g,'').replace(/-/g,'').trim();
      case 'wialon_ts':          return iso;
      case 'fecha_hora': {
        if (isNaN(d)) return iso;
        return `${pad(d.getUTCDate())}-${pad(d.getUTCMonth()+1)}-${d.getUTCFullYear()} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
      }
      case 'fecha_utc': {
        if (isNaN(d)) return iso;
        return `${d.getUTCFullYear()}-${pad(d.getUTCMonth()+1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
      }
      case 'fecha_chile_iso': {
        const loc = chile();
        return `${loc.getFullYear()}-${pad(loc.getMonth()+1)}-${pad(loc.getDate())} ${pad(loc.getHours())}:${pad(loc.getMinutes())}:${pad(loc.getSeconds())}`;
      }
      case 'fecha_chile': {
        const loc = chile();
        return `${pad(loc.getDate())}-${pad(loc.getMonth()+1)}-${loc.getFullYear()} ${pad(loc.getHours())}:${pad(loc.getMinutes())}:${pad(loc.getSeconds())}`;
      }
      case 'fecha_utc_off': {
        if (isNaN(d)) return iso;
        return `${d.getUTCFullYear()}-${pad(d.getUTCMonth()+1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())} +00:00`;
      }
      case 'sitrack_evento': {
        const ign = ev.ignition === true || ev.ignition === 1;
        return ign ? 163 : 164;
      }
      case 'skynav_evento': {
        const ign    = ev.ignition === true || ev.ignition === 1;
        const moving = Number(ev.speed || 0) > 0;
        if (moving) return ign ? 41 : 52;
        return ign ? 51 : 42;
      }
      case 'unix_timestamp':    return Math.floor(new Date(iso).getTime() / 1000);
      case 'unix_timestamp_ms': return new Date(iso).getTime();
      case 'address':           return '[reverse_geocoding — ver logs Railway]';
      default:                  return `[${source}]`;
    }
  }

  // Construir payload por destino — misma lógica que buildPayload del tcp-server
  const payloads = {};

  for (const dest of destRows) {
    if (dest.shadow) {
      payloads[dest.name] = { _info: 'shadow — registra pero no envía' };
      continue;
    }
    if (dest.driver_slug) {
      payloads[dest.name] = { _info: `driver:${dest.driver_slug} — payload manejado internamente, ver logs Railway` };
      continue;
    }

    let schema = [];
    try {
      schema = typeof dest.field_schema === 'string'
        ? JSON.parse(dest.field_schema)
        : (dest.field_schema || []);
    } catch (_) {}

    // Sin schema → payload genérico
    if (!schema.length) {
      payloads[dest.name] = {
        imei:     unit.imei,
        plate:    unit.plate,
        lat:      ev.lat,
        lon:      ev.lon,
        speed:    ev.speed,
        heading:  ev.heading,
        ignition: ev.ignition,
        ts:       ev.wialon_ts,
      };
      continue;
    }

    const obj     = {};
    const missing = [];

    for (const f of schema.sort((a, b) => (a.order || 0) - (b.order || 0))) {
      // Mismo isFixed que buildPayload del tcp-server
      const isFixed =
        f.source === 'fixed' ||
        ((!f.source || f.source === '') && f.fixedValue !== undefined && f.fixedValue !== null && f.fixedValue !== '');

      const val = isFixed
        ? f.fixedValue
        : resolveSource(f.source, f.fixedValue);

      const isEmpty = val === null || val === undefined || val === '';

      if (isEmpty && f.required) {
        missing.push(f.apiKey);
      } else {
        obj[f.apiKey] = val;
      }
    }

    if (missing.length) obj._campos_faltantes_required = missing;
    payloads[dest.name] = obj;
  }

  res.json({
    imei,
    plate:         unit.plate,
    cliente:       unit.cliente_nombre || unit.name,
    ultimo_evento: ev.received_at || null,
    payloads,
  });
});

module.exports = router;
