/**
 * db/migrate.js
 * Ejecuta las migraciones pendientes al arrancar el servidor.
 * Seguro de correr múltiples veces (idempotente).
 *
 * Uso: se llama automáticamente desde index.js al iniciar.
 */

const { query } = require('./pool');

const migrations = [
  {
    name: '001_add_field_schema_to_destinations',
    sql: `
      ALTER TABLE public.destinations
      ADD COLUMN IF NOT EXISTS field_schema JSONB DEFAULT '[]'::jsonb;
    `
  },
  {
    name: '002_add_api_url_to_destinations',
    sql: `
      ALTER TABLE public.destinations
      ADD COLUMN IF NOT EXISTS api_url TEXT;
    `
  },
  {
    name: '003_add_color_to_destinations',
    sql: `
      ALTER TABLE public.destinations
      ADD COLUMN IF NOT EXISTS color TEXT DEFAULT '#38bdf8';
    `
  },
];

async function runMigrations() {
  // Tabla de control de migraciones
  await query(`
    CREATE TABLE IF NOT EXISTS public._migrations (
      name       TEXT PRIMARY KEY,
      applied_at TIMESTAMPTZ DEFAULT now()
    )
  `);

  for (const m of migrations) {
    const { rows } = await query(
      'SELECT 1 FROM public._migrations WHERE name = $1',
      [m.name]
    );

    if (rows.length === 0) {
      console.log(`[migrate] Aplicando: ${m.name}`);
      await query(m.sql);
      await query(
        'INSERT INTO public._migrations (name) VALUES ($1)',
        [m.name]
      );
      console.log(`[migrate] ✓ ${m.name}`);
    }
  }

  console.log('[migrate] Migraciones al día.');
}

module.exports = { runMigrations };
