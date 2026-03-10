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
  {
  name: '004_create_roles_table',
  sql: `
    CREATE TABLE IF NOT EXISTS public.roles (
      id         TEXT PRIMARY KEY,
      label      TEXT NOT NULL,
      modules    JSONB NOT NULL DEFAULT '["dashboard","validador"]'::jsonb,
      created_at TIMESTAMPTZ DEFAULT now(),
      updated_at TIMESTAMPTZ DEFAULT now()
    );
  `
},
{
  name: '005_add_role_id_to_users',
  sql: `
    ALTER TABLE public.users
    ADD COLUMN IF NOT EXISTS role_id TEXT REFERENCES public.roles(id) ON DELETE SET NULL;
  `
},
{
  name: '006_add_rut_to_units',
  sql: `ALTER TABLE public.units ADD COLUMN IF NOT EXISTS rut VARCHAR(20);`
},
{
  name: '007_create_clientes_table',
  sql: `
    CREATE TABLE IF NOT EXISTS public.clientes (
      id         VARCHAR(36)  PRIMARY KEY,
      nombre     VARCHAR(255) NOT NULL,
      rut        VARCHAR(20),
      token      VARCHAR(64)  UNIQUE NOT NULL,
      enabled    BOOLEAN      DEFAULT true,
      created_at TIMESTAMPTZ  DEFAULT now(),
      updated_at TIMESTAMPTZ  DEFAULT now()
    );
  `
},
{
  name: '008_add_cliente_id_to_units',
  sql: `
    ALTER TABLE public.units
    ADD COLUMN IF NOT EXISTS cliente_id VARCHAR(36)
    REFERENCES public.clientes(id) ON DELETE SET NULL;
  `
},
{
  name: '009_add_password_hash_to_clientes',
  sql: `
    ALTER TABLE public.clientes
    ADD COLUMN IF NOT EXISTS password_hash TEXT;
  `
},
{
  name: '010_create_certificados_table',
  sql: `
    CREATE TABLE IF NOT EXISTS public.certificados (
      id                UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
      patente           VARCHAR(20)  NOT NULL,
      imei              VARCHAR(50)  NOT NULL,
      empresa           VARCHAR(255),
      rut_empresa       VARCHAR(20),
      firmante          VARCHAR(255),
      rut_firmante      VARCHAR(20),
      fecha_emision     DATE         NOT NULL,
      fecha_vencimiento DATE         NOT NULL,
      validez_texto     VARCHAR(100),
      estado            VARCHAR(20)  NOT NULL DEFAULT 'vigente',
      invalidado_por    VARCHAR(100),
      invalidado_at     TIMESTAMPTZ,
      emitido_por       VARCHAR(100),
      created_at        TIMESTAMPTZ  DEFAULT now()
    );
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
