/**
 * middleware/auth.js
 * Verifica el JWT en cada request protegido.
 * También valida que el usuario siga habilitado en DB.
 */

const jwt     = require('jsonwebtoken');
const { query } = require('../db/pool');

/**
 * requireAuth — valida JWT y adjunta req.user
 */
async function requireAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token requerido.' });
  }

  const token = header.slice(7);
  let payload;

  try {
    payload = jwt.verify(token, process.env.JWT_SECRET);
  } catch (err) {
    return res.status(401).json({ error: 'Token inválido o expirado.' });
  }

  // Re-verificar que el usuario siga activo en DB
  const { rows } = await query(
    'SELECT id, username, role, enabled FROM public.users WHERE id = $1',
    [payload.sub]
  );

  if (!rows.length || !rows[0].enabled) {
    return res.status(401).json({ error: 'Usuario deshabilitado o no encontrado.' });
  }

  req.user = rows[0];
  next();
}

/**
 * requireRole('admin') — solo permite un rol específico
 */
function requireRole(role) {
  return (req, res, next) => {
    if (req.user?.role !== role) {
      return res.status(403).json({ error: 'Sin permisos para esta acción.' });
    }
    next();
  };
}

module.exports = { requireAuth, requireRole };
