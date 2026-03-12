/**
 * admin.js — Rutas de administración del sistema
 *
 * GET /admin/system-info  → información del servidor (solo admins)
 */

const express  = require('express');
const os       = require('os');
const { pool } = require('../db/pool');
const { requireAuth, requireRole } = require('../middleware/auth');

const router = express.Router();

/* ── GET /admin/system-info ────────────────────────────────────── */
router.get('/system-info', requireAuth, requireRole('admin'), async (_req, res) => {
  try {
    // Estadísticas de BD
    const [unitsRes, clientesRes, destRes, certsRes, usersRes] = await Promise.all([
      pool.query('SELECT COUNT(*) FROM units'),
      pool.query('SELECT COUNT(*) FROM clientes'),
      pool.query('SELECT COUNT(*) FROM destinations'),
      pool.query("SELECT COUNT(*) FROM certificados WHERE estado = 'vigente'"),
      pool.query('SELECT COUNT(*) FROM users'),
    ]);

    // Uptime en formato legible
    const uptimeSec = process.uptime();
    const h  = Math.floor(uptimeSec / 3600);
    const m  = Math.floor((uptimeSec % 3600) / 60);
    const s  = Math.floor(uptimeSec % 60);
    const uptimeStr = `${h}h ${m}m ${s}s`;

    // Memoria
    const memUsed = process.memoryUsage();
    const toMB    = (bytes) => (bytes / 1024 / 1024).toFixed(1) + ' MB';

    res.json({
      // Servidor
      version:    process.env.npm_package_version || '1.0.0',
      node:       process.version,
      env:        process.env.NODE_ENV || 'production',
      platform:   process.platform,
      uptime:     uptimeStr,
      uptime_sec: Math.floor(uptimeSec),

      // Memoria
      memory: {
        rss:        toMB(memUsed.rss),
        heap_used:  toMB(memUsed.heapUsed),
        heap_total: toMB(memUsed.heapTotal),
      },

      // SO
      os: {
        hostname: os.hostname(),
        type:     os.type(),
        arch:     os.arch(),
        cpus:     os.cpus().length,
        free_mem: toMB(os.freemem()),
      },

      // Conteos — estructura que espera el frontend (info.counts.*)
      counts: {
        units:          parseInt(unitsRes.rows[0].count),
        clientes:       parseInt(clientesRes.rows[0].count),
        users:          parseInt(usersRes.rows[0].count),
        destinations:   parseInt(destRes.rows[0].count),
        certs_vigentes: parseInt(certsRes.rows[0].count),
      },

      // DB status
      db: 'connected',

      ts: new Date().toISOString(),
    });
  } catch (err) {
    console.error('[admin/system-info] Error:', err.message);
    res.status(500).json({ error: 'No se pudo obtener información del sistema.' });
  }
});

module.exports = router;
