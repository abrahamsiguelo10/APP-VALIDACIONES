/**
 * index.js — Servidor principal Síguelo API
 */
require('dotenv').config();
const express = require('express');
const cors    = require('cors');
const { pool }          = require('./db/pool');
const { runMigrations } = require('./db/migrate');
const { startTcpServer } = require('./tcp-server');
const authRoutes      = require('./routes/auth');
const userRoutes      = require('./routes/users');
const destRoutes      = require('./routes/destinations');
const unitRoutes      = require('./routes/units');
const roleRoutes      = require('./routes/roles');
const clienteRoutes   = require('./routes/clientes');
const validadorRoutes = require('./routes/validador');
const gpsProxyRoutes  = require('./routes/gps-proxy');
const certRoutes      = require('./routes/certificados');
const adminRoutes     = require('./routes/admin');

const app  = express();
const PORT = process.env.PORT || 3000;

app.set('trust proxy', 1);

/* ── Forzar headers CORS antes de cualquier middleware ────────── */
// Esto asegura que OPTIONS siempre reciba los headers correctos
// independiente de proxies o middlewares que puedan interceptar
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && isOriginAllowed(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Credentials', 'true');

  // Responder preflight inmediatamente
  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }
  next();
});

/* ── CORS ─────────────────────────────────────────────────────── */
// Orígenes permitidos: variable de entorno + siempre el .vercel.app base
const _corsOrigins = (process.env.CORS_ORIGIN || '')
  .split(',')
  .map(o => o.trim())
  .filter(Boolean);

function isOriginAllowed(origin) {
  if (!origin) return true; // server-to-server sin Origin
  if (_corsOrigins.includes('*')) return true;
  if (_corsOrigins.includes(origin)) return true;
  // Permitir cualquier subdominio de siguelogps.com
  if (/^https:\/\/[a-z0-9-]+\.siguelogps\.com$/.test(origin)) return true;
  // Permitir el dominio de Vercel del proyecto
  if (/^https:\/\/app-validaciones[a-z0-9-]*\.vercel\.app$/.test(origin)) return true;
  return false;
}

app.use(cors({
  origin: (origin, callback) => {
    if (isOriginAllowed(origin)) {
      callback(null, origin || '*');
    } else {
      console.warn(`[CORS] Origen bloqueado: ${origin}`);
      callback(new Error(`Origen no permitido por CORS: ${origin}`));
    }
  },
  methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
}));

/* ── Body parser ──────────────────────────────────────────────── */
app.use(express.json({ limit: '1mb' }));

/* ── Health check ─────────────────────────────────────────────── */
app.get('/health', async (_req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'ok', db: 'connected', ts: new Date().toISOString() });
  } catch {
    res.status(503).json({ status: 'error', db: 'disconnected' });
  }
});

/* ── Rutas ────────────────────────────────────────────────────── */
app.use('/auth',         authRoutes);
app.use('/users',        userRoutes);
app.use('/destinations', destRoutes);
app.use('/units',        unitRoutes);
app.use('/roles',        roleRoutes);
app.use('/clientes',     clienteRoutes);
app.use('/validador',    validadorRoutes);
app.use('/gps',          gpsProxyRoutes);
app.use('/certificados', certRoutes);
app.use('/admin',        adminRoutes);

/* ── 404 ──────────────────────────────────────────────────────── */
app.use((_req, res) => {
  res.status(404).json({ error: 'Endpoint no encontrado.' });
});

/* ── Error handler global ─────────────────────────────────────── */
app.use((err, _req, res, _next) => {
  console.error('[ERROR]', err.message);
  const status = err.status ?? 500;
  res.status(status).json({
    error: status === 500
      ? 'Error interno del servidor.'
      : err.message
  });
});

/* ── Arranque ─────────────────────────────────────────────────── */
async function start() {
  try {
    await runMigrations();
    if (process.env.TCP_ENABLED !== 'false') {
      startTcpServer();
    }
    app.listen(PORT, () => {
      console.log(`✓ Síguelo API escuchando en puerto ${PORT}`);
      console.log(`  CORS orígenes: ${_corsOrigins.join(', ') || '(solo siguelogps.com y vercel.app)'}`);
      console.log(`  NODE_ENV: ${process.env.NODE_ENV ?? 'development'}`);
    });
  } catch (err) {
    console.error('Error fatal al arrancar:', err);
    process.exit(1);
  }
}
start();
