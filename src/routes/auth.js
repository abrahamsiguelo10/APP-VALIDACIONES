/**
 * routes/auth.js
 * POST  /auth/login
 * POST  /auth/logout
 * PATCH /auth/me     — actualizar username y/o contraseña del usuario autenticado
 */

const router  = require('express').Router();
const bcrypt  = require('bcrypt');
const jwt     = require('jsonwebtoken');
const { query } = require('../db/pool');
const audit   = require('../middleware/audit');

/* ── Middleware auth local ────────────────────────────────────── */
function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) return res.status(401).json({ error: 'No autorizado.' });
  try {
    req.user = jwt.verify(auth.slice(7), process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Sesión expirada.' });
  }
}

/* ── POST /auth/login ─────────────────────────────────────────── */
router.post('/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Usuario y contraseña requeridos.' });
  }

  const { rows } = await query(
    `SELECT id, username, password_hash, role, enabled
     FROM public.users
     WHERE username = $1`,
    [username.trim().toLowerCase()]
  );

  const user = rows[0];

  if (!user) {
    return res.status(401).json({ error: 'Usuario o contraseña incorrectos.' });
  }

  if (!user.enabled) {
    return res.status(403).json({ error: 'Tu cuenta está deshabilitada. Contacta al administrador.' });
  }

  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) {
    return res.status(401).json({ error: 'Usuario o contraseña incorrectos.' });
  }

  const token = jwt.sign(
    { sub: user.id, username: user.username, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN || '8h' }
  );

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
router.post('/logout', async (req, res) => {
  const header = req.headers.authorization;
  if (header?.startsWith('Bearer ')) {
    try {
      const payload = jwt.verify(header.slice(7), process.env.JWT_SECRET);
      await audit.log({
        req: { ...req, user: { username: payload.username, role: payload.role } },
        action: 'LOGOUT',
        target: payload.username,
      });
    } catch (_) {}
  }
  return res.json({ ok: true });
});

/* ── PATCH /auth/me ───────────────────────────────────────────── */
// Permite al usuario autenticado cambiar su username y/o contraseña.
router.patch('/me', requireAuth, async (req, res) => {
  const { username, currentPassword, newPassword } = req.body;
  const userId = req.user.sub;

  // Buscar usuario actual
  const { rows } = await query(
    'SELECT id, username, password_hash, role FROM public.users WHERE id = $1',
    [userId]
  );
  const user = rows[0];
  if (!user) return res.status(404).json({ error: 'Usuario no encontrado.' });

  const updates = [];
  const values  = [];
  let idx = 1;

  // ── Cambio de username ──
  if (username && username.trim() !== user.username) {
    const newName = username.trim().toLowerCase();
    if (newName.length < 3) return res.status(400).json({ error: 'El usuario debe tener al menos 3 caracteres.' });
    // Verificar que no exista
    const { rows: existing } = await query(
      'SELECT id FROM public.users WHERE username = $1 AND id != $2',
      [newName, userId]
    );
    if (existing.length) return res.status(409).json({ error: 'Ese nombre de usuario ya está en uso.' });
    updates.push(`username = $${idx++}`);
    values.push(newName);
  }

  // ── Cambio de contraseña ──
  if (newPassword) {
    if (!currentPassword) return res.status(400).json({ error: 'Debes ingresar tu contraseña actual.' });
    const valid = await bcrypt.compare(currentPassword, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Contraseña actual incorrecta.' });
    if (newPassword.length < 6) return res.status(400).json({ error: 'La nueva contraseña debe tener al menos 6 caracteres.' });
    const hash = await bcrypt.hash(newPassword, 10);
    updates.push(`password_hash = $${idx++}`);
    values.push(hash);
  }

  if (!updates.length) return res.status(400).json({ error: 'Nada que actualizar.' });

  values.push(userId);
  const { rows: updated } = await query(
    `UPDATE public.users SET ${updates.join(', ')} WHERE id = $${idx} RETURNING id, username, role`,
    values
  );

  // Emitir nuevo token con username actualizado
  const newToken = jwt.sign(
    { sub: updated[0].id, username: updated[0].username, role: updated[0].role },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN || '8h' }
  );

  return res.json({ ok: true, token: newToken, user: updated[0] });
});

module.exports = router;
