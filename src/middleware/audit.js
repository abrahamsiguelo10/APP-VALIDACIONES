/**
 * middleware/audit.js
 * Registra acciones importantes en public.audit_log.
 * Usar como función helper, no como middleware global.
 */

const { query } = require('../db/pool');

/**
 * log({ req, action, target, before, after })
 */
async function log({ req, action, target = null, before = null, after = null }) {
  try {
    await query(
      `INSERT INTO public.audit_log
         (actor, role, action, target, before_json, after_json, ip, user_agent)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [
        req.user?.username ?? 'sistema',
        req.user?.role     ?? 'system',
        action,
        target,
        before ? JSON.stringify(before) : null,
        after  ? JSON.stringify(after)  : null,
        req.ip ?? req.headers['x-forwarded-for'] ?? null,
        req.headers['user-agent'] ?? null,
      ]
    );
  } catch (err) {
    // No cortar el flujo si el log falla
    console.error('[audit] Error al registrar:', err.message);
  }
}

module.exports = { log };
