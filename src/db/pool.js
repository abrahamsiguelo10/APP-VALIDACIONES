/**
 * db/pool.js
 * Pool de conexiones a PostgreSQL (Supabase).
 * Todas las queries pasan por aquí.
 */

const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false   // requerido por Supabase
  },
  max: 10,                      // máximo de conexiones simultáneas
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 5_000,
});

pool.on('error', (err) => {
  console.error('[DB] Error inesperado en cliente idle:', err.message);
});

/**
 * Ejecuta una query parametrizada.
 * @param {string} text  — SQL con $1, $2…
 * @param {any[]}  params
 */
async function query(text, params) {
  const start = Date.now();
  const res   = await pool.query(text, params);
  const ms    = Date.now() - start;
  if (process.env.NODE_ENV !== 'production') {
    console.log(`[DB] ${ms}ms → ${text.slice(0, 80)}`);
  }
  return res;
}

module.exports = { pool, query };
