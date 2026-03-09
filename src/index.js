/**
 * index.js — Servidor principal Síguelo API
 *
 * Orden de arranque:
 *  1. Cargar .env
 *  2. Conectar DB y correr migraciones
 *  3. Montar middlewares globales
 *  4. Montar rutas
 *  5. Error handler global
 *  6. Escuchar puerto
 */

require('dotenv').config();

const express = require('express');
const cors    = require('cors');

const { pool }          = require('./db/pool');
const { runMigrations } = require('./db/migrate');

const authRoutes      = require('./routes/auth');
const userRoutes      = require('./routes/users');
const destRoutes      = require('./routes/destinations');
const unitRoutes      = require('./routes/units');
const roleRoutes      = require('./routes/roles');
const clienteRoutes   = require('./routes/clientes');
const validadorRoutes = require('./routes/validador');
const gpsProxyRoutes  = require('./routes/gps-proxy');

const app  = express();
const PORT = process.env.PORT || 3000;

/* ── CORS ─────────────────────────────────────────────────────── */
app.use(cors({
  origin: process.env.CORS_ORIGIN?.split(',') ?? '*',
  methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
}));

/* ── Body parser ──────────────────────────────────────────────── */
app.use(express.json({ limit: '1mb' }));

/* ── Health check (Railway lo usa para saber si está vivo) ─────── */
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
    app.listen(PORT, () => {
      console.log(`✓ Síguelo API escuchando en puerto ${PORT}`);
      console.log(`  NODE_ENV: ${process.env.NODE_ENV ?? 'development'}`);
    });
  } catch (err) {
    console.error('Error fatal al arrancar:', err);
    process.exit(1);
  }
}

start();
