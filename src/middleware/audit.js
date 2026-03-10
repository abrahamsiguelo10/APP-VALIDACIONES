// middleware/audit.js
// Registra acciones importantes en la tabla audit_log

const { pool } = require('../db/pool');

async function log({ req, action, target, before, after }) {
  try {
    // Protección defensiva — req puede llegar parcial
    const headers = req?.headers || {};
    const ip = headers['x-forwarded-for']?.split(',')[0]?.trim()
      || req?.ip
      || req?.socket?.remoteAddress
      || 'unknown';

    const userId   = req?.user?.id       || req?.user?.sub || null;
    const username = req?.user?.username || req?.user?.rut || null;
    const role     = req?.user?.role     || req?.user?.tipo || null;

    await pool.query(
      `INSERT INTO public.audit_log
         (action, target, before_data, after_data, user_id, username, role, ip, created_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,now())`,
      [
        action,
        target   || null,
        before   ? JSON.stringify(before) : null,
        after    ? JSON.stringify(after)  : null,
        userId,
        username,
        role,
        ip,
      ]
    );
  } catch (err) {
    // No dejar que un fallo de audit rompa la petición principal
    console.error('[audit] Error al registrar:', err.message);
  }
}

module.exports = { log };
