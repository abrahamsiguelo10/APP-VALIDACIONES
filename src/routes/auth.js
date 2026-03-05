/**
 * routes/auth.js
 * POST /auth/login
 * POST /auth/logout  (stateless — solo referencia en cliente)
 */

const router  = require('express').Router();
const bcrypt  = require('bcrypt');
const jwt     = require('jsonwebtoken');
const { query } = require('../db/pool');
const audit   = require('../middleware/audit');

/* ── POST /auth/login ─────────────────────────────────────────── */
router.post('/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Usuario y contraseña requeridos.' });
  }

  // Buscar usuario
  const { rows } = await query(
    `SELECT id, username, password_hash, role, enabled
     FROM public.users
     WHERE username = $1`,
    [username.trim().toLowerCase()]
  );

  const user = rows[0];

  // Usuario no existe → mismo mensaje que contraseña incorrecta (seguridad)
  if (!user) {
    return res.status(401).json({ error: 'Usuario o contraseña incorrectos.' });
  }

  // Usuario deshabilitado
  if (!user.enabled) {
    return res.status(403).json({ error: 'Tu cuenta está deshabilitada. Contacta al administrador.' });
  }

  // Verificar contraseña
  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) {
    return res.status(401).json({ error: 'Usuario o contraseña incorrectos.' });
  }

  // Emitir JWT
  const token = jwt.sign(
    { sub: user.id, username: user.username, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN || '8h' }
  );

  // Registrar en audit_log
  await audit.log({
    req: { ...req, user: { username: user.username, role: user.role } },
    action: 'LOGIN',
    target: user.username,
  });

  return res.json({
    token,
    user: {
      id:       user.id,
      username: user.username,
      role:     user.role,
    }
  });
});

/* ── POST /auth/logout ────────────────────────────────────────── */
// JWT es stateless: el cliente simplemente descarta el token.
// Este endpoint existe para registrar el logout en audit_log.
router.post('/logout', async (req, res) => {
  const header = req.headers.authorization;
  if (header?.startsWith('Bearer ')) {
    try {
      const payload = jwt.verify(
        header.slice(7),
        process.env.JWT_SECRET
      );
      await audit.log({
        req: { ...req, user: { username: payload.username, role: payload.role } },
        action: 'LOGOUT',
        target: payload.username,
      });
    } catch (_) { /* token expirado — ignorar */ }
  }
  return res.json({ ok: true });
});

module.exports = router;
