/**
 * routes/admin.js
 */
const router = require('express').Router();
const { query } = require('../db/pool');
const { requireAuth, requireRole } = require('../middleware/auth');

router.use(requireAuth);

/* ── GET /admin/system-info ──────────────────────────────────── */
router.get('/system-info', requireRole('admin'), async (_req, res) => {
  try {
    const [units, dests, users, events] = await Promise.all([
      query('SELECT COUNT(*) FROM public.units'),
      query('SELECT COUNT(*) FROM public.unit_destinations WHERE enabled = true'),
      query('SELECT COUNT(*) FROM public.users'),
      query('SELECT COUNT(*) FROM public.gps_events'),
    ]);
    res.json({
      units:  parseInt(units.rows[0].count),
      dests:  parseInt(dests.rows[0].count),
      users:  parseInt(users.rows[0].count),
      events: parseInt(events.rows[0].count),
      db:     'connected',
      uptime: Math.floor(process.uptime()),
      ts:     new Date().toISOString(),
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* ── GET /admin/audit ────────────────────────────────────────── */
router.get('/audit', requireRole('admin'), async (req, res) => {
  try {
    const {
      limit  = 100,
      offset = 0,
      action,
      username,
      from,
      to,
      search,
    } = req.query;

    const conditions = [];
    const values     = [];
    let   i          = 1;

    if (action)   { conditions.push(`action ILIKE $${i++}`);   values.push(`%${action}%`); }
    if (username) { conditions.push(`username ILIKE $${i++}`); values.push(`%${username}%`); }
    if (from)     { conditions.push(`created_at >= $${i++}`);  values.push(from); }
    if (to)       { conditions.push(`created_at <= $${i++}`);  values.push(to); }
    if (search)   {
      conditions.push(`(action ILIKE $${i} OR target ILIKE $${i} OR username ILIKE $${i})`);
      values.push(`%${search}%`); i++;
    }

    const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';

    const [rows, total] = await Promise.all([
      query(
        `SELECT id, action, target, before_data, after_data,
                user_id, username, role, ip, created_at
         FROM public.audit_log
         ${where}
         ORDER BY created_at DESC
         LIMIT $${i++} OFFSET $${i++}`,
        [...values, parseInt(limit), parseInt(offset)]
      ),
      query(`SELECT COUNT(*) FROM public.audit_log ${where}`, values),
    ]);

    res.json({
      rows:  rows.rows,
      total: parseInt(total.rows[0].count),
      limit: parseInt(limit),
      offset: parseInt(offset),
    });
  } catch (err) {
    if (err.message?.includes('column') && err.message?.includes('does not exist')) {
      return res.json({ rows: [], total: 0,
        limit:  parseInt(req.query.limit  || 100),
        offset: parseInt(req.query.offset || 0),
        warning: 'Migraciones pendientes.' });
    }
    res.status(500).json({ error: err.message });
  }
});

/* ── POST /admin/test-token — prueba un token contra una URL externa ── */
router.post('/test-token', requireRole('admin'), async (req, res) => {
  const { url, token, payload } = req.body;
  if (!url || !token) return res.status(400).json({ error: 'url y token requeridos.' });

  const testPayload = payload || [{
    fechaHora: new Date().toISOString().slice(0,19).replace('T',' '),
    latitud: -32.8, longitud: -71.2,
    patente: 'TEST01', provider: 'siguelo_gps',
    imei: '000000000000001',
    evento: 42, velocidad: 0, heading: 0, ignicion: 0,
  }];

  try {
    const r = await fetch(url, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
      body:    JSON.stringify(testPayload),
      signal:  AbortSignal.timeout ? AbortSignal.timeout(10000) : undefined,
    });
    const body = await r.text().catch(() => '');
    res.json({ http_status: r.status, ok: r.ok, body: body.slice(0, 500) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
