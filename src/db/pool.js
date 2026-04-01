/**
 * db/pool.js
 * Pool de conexiones a PostgreSQL (Supabase).
 * Todas las queries pasan por aquí.
 */
const { Pool } = require('pg');

// ── Calcular max conexiones según el plan ─────────────────────────
// Supabase Free:  20-60 conexiones disponibles → usar máx 20
// Supabase Pro:   200+ conexiones disponibles  → usar máx 50
// Se puede sobreescribir con DB_POOL_MAX en Railway
const MAX_CONNECTIONS = parseInt(process.env.DB_POOL_MAX || '20', 10);

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false, // requerido por Supabase
  },
  max:                    MAX_CONNECTIONS,
  min:                    2,          // mantener al menos 2 conexiones listas
  idleTimeoutMillis:      30_000,     // cerrar conexiones inactivas a los 30s
  connectionTimeoutMillis: 3_000,     // timeout para obtener conexión (antes 5s)
  allowExitOnIdle:        false,      // no cerrar el pool si está idle
});

// ── Logs de estado del pool ───────────────────────────────────────
pool.on('connect', () => {
  if (process.env.NODE_ENV !== 'production') {
    console.log(`[DB] Nueva conexión (total: ${pool.totalCount})`);
  }
});

pool.on('error', (err) => {
  console.error('[DB] Error inesperado en cliente idle:', err.message);
});

// Log de estado del pool cada 5 minutos en producción
if (process.env.NODE_ENV === 'production') {
  setInterval(() => {
    console.log(
      `[DB] Pool — total:${pool.totalCount} idle:${pool.idleCount} waiting:${pool.waitingCount}`
    );
  }, 5 * 60 * 1000);
}

/**
 * Ejecuta una query parametrizada.
 * @param {string} text   — SQL con $1, $2…
 * @param {any[]}  params — parámetros opcionales
 */
async function query(text, params) {
  const start = Date.now();
  try {
    const res = await pool.query(text, params);
    const ms  = Date.now() - start;
    if (process.env.NODE_ENV !== 'production') {
      console.log(`[DB] ${ms}ms → ${text.slice(0, 80)}`);
    }
    // Alerta si una query tarda más de 2 segundos
    if (ms > 2000) {
      console.warn(`[DB] Query lenta (${ms}ms): ${text.slice(0, 120)}`);
    }
    return res;
  } catch (err) {
    console.error(`[DB] Error en query: ${err.message} | SQL: ${text.slice(0, 120)}`);
    throw err;
  }
}

module.exports = { pool, query };
