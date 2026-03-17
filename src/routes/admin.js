/**
 * routes/admin.js
 * GET /admin/system-info  — info del sistema
 * GET /admin/audit        — historial de cambios (admin)
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
      query('SELECT COUNT(*) FROM public.destinations'),
      query('SELECT COUNT(*) FROM public.users'),
      query('SELECT COUNT(*) FROM public.gps_events'),
    ]);
    res.json({
      units:  parseInt(units.rows[0].count),
      dests:  parseInt(dests.rows[0].count),
      users:  parseInt(users.rows[0].count),
      events: parseInt(events.rows[0].count),
      ts: new Date().toISOString(),
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
        `SELECT
           id, action, target, created_at,
           COALESCE(user_id,  '')   AS user_id,
           COALESCE(username, '—')  AS username,
           COALESCE(role,     '')   AS role,
           COALESCE(ip,       '')   AS ip,
           before_data,
           after_data
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
    // Si la columna no existe aún, devolver estructura vacía en vez de error 500
    if (err.message?.includes('column') && err.message?.includes('does not exist')) {
      return res.json({ rows: [], total: 0, limit: parseInt(limit), offset: 0,
        warning: 'Ejecuta las migraciones pendientes para activar el historial.' });
    }
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
