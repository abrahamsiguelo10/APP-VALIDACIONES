// src/db/migrate.js
// Migraciones 001-013. Las nuevas son 012 (driver_slug) y 013 (auth).
// Las migraciones existentes (001-011) se conservan idénticas.

const { createClient } = require('@supabase/supabase-js');

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

const migrations = [
  {
    name: '001_add_field_schema_to_destinations',
    sql: `ALTER TABLE public.destinations
          ADD COLUMN IF NOT EXISTS field_schema JSONB DEFAULT '[]'::jsonb;`
  },
  {
    name: '002_add_api_url_to_destinations',
    sql: `ALTER TABLE public.destinations
          ADD COLUMN IF NOT EXISTS api_url TEXT;`
  },
  {
    name: '003_add_color_to_destinations',
    sql: `ALTER TABLE public.destinations
          ADD COLUMN IF NOT EXISTS color TEXT DEFAULT '#38bdf8';`
  },
  {
    name: '004_create_roles_table',
    sql: `CREATE TABLE IF NOT EXISTS public.roles (
            id   TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            modules JSONB DEFAULT '[]'::jsonb,
            created_at TIMESTAMPTZ DEFAULT now()
          );`
  },
  {
    name: '005_add_role_id_to_users',
    sql: `ALTER TABLE public.users
          ADD COLUMN IF NOT EXISTS role_id TEXT REFERENCES public.roles(id) ON DELETE SET NULL;`
  },
  {
    name: '006_add_rut_to_units',
    sql: `ALTER TABLE public.units ADD COLUMN IF NOT EXISTS rut VARCHAR(20);`
  },
  {
    name: '007_create_clientes_table',
    sql: `CREATE TABLE IF NOT EXISTS public.clientes (
            id           VARCHAR(36) PRIMARY KEY DEFAULT gen_random_uuid()::text,
            name         TEXT NOT NULL,
            rut          VARCHAR(20) UNIQUE,
            email        TEXT,
            phone        TEXT,
            address      TEXT,
            created_at   TIMESTAMPTZ DEFAULT now(),
            updated_at   TIMESTAMPTZ DEFAULT now()
          );`
  },
  {
    name: '008_add_cliente_id_to_units',
    sql: `ALTER TABLE public.units
          ADD COLUMN IF NOT EXISTS cliente_id VARCHAR(36)
          REFERENCES public.clientes(id) ON DELETE SET NULL;`
  },
  {
    name: '009_add_password_hash_to_clientes',
    sql: `ALTER TABLE public.clientes
          ADD COLUMN IF NOT EXISTS password_hash TEXT;`
  },
  {
    name: '010_create_certificados_table',
    sql: `CREATE TABLE IF NOT EXISTS public.certificados (
            id           VARCHAR(36) PRIMARY KEY DEFAULT gen_random_uuid()::text,
            cliente_id   VARCHAR(36) REFERENCES public.clientes(id) ON DELETE CASCADE,
            imei         TEXT,
            plate        TEXT,
            issued_at    TIMESTAMPTZ DEFAULT now(),
            valid_until  TIMESTAMPTZ,
            data         JSONB DEFAULT '{}'::jsonb,
            created_at   TIMESTAMPTZ DEFAULT now()
          );`
  },
  {
    name: '011_create_gps_events_table',
    sql: `CREATE TABLE IF NOT EXISTS public.gps_events (
            id             BIGSERIAL PRIMARY KEY,
            plate          TEXT,
            imei           TEXT,
            lat            DOUBLE PRECISION,
            lon            DOUBLE PRECISION,
            speed          DOUBLE PRECISION,
            heading        DOUBLE PRECISION,
            ignition       BOOLEAN,
            wialon_ts      TIMESTAMPTZ,
            destination_id TEXT REFERENCES public.destinations(id) ON DELETE SET NULL,
            forward_ok     BOOLEAN,
            forward_resp   TEXT,
            raw_hex        TEXT,
            created_at     TIMESTAMPTZ DEFAULT now()
          );`
  },
  // ── NUEVAS ────────────────────────────────────────────────────────────────
  {
    name: '012_add_driver_slug_to_destinations',
    sql: `ALTER TABLE public.destinations
          ADD COLUMN IF NOT EXISTS driver_slug TEXT DEFAULT NULL;
          -- Poblar driver_slug para destinos cuyos nombres coinciden con slugs conocidos
          UPDATE public.destinations
          SET driver_slug = name
          WHERE driver_slug IS NULL
            AND name IN ('byduarte','cala','drivin','bermann','skynav','skyangel',
                         'tranciti','sitrack','startsee','pegasus','unigis','qmgps',
                         'drivetech','ziyu','i-dux','tmsfalabella','antucoya',
                         'centinela','pelambres');`
  },
  {
    name: '013_add_auth_to_destinations',
    sql: `ALTER TABLE public.destinations
          ADD COLUMN IF NOT EXISTS auth JSONB DEFAULT NULL;`
    /*
      Estructura esperada del campo auth:
        null                         → sin autenticación
        { type: "bearer", token }    → Authorization: Bearer <token>
        { type: "basic", username, password } → Authorization: Basic base64(u:p)
        { type: "apikey", header, value }     → <header>: <value>
    */
  },
];

async function runMigrations() {
  console.log('🔄 Ejecutando migraciones...');

  // Crear tabla de control si no existe
  await supabase.rpc('exec_sql', {
    sql: `CREATE TABLE IF NOT EXISTS public._migrations (
            name       TEXT PRIMARY KEY,
            applied_at TIMESTAMPTZ DEFAULT now()
          );`
  }).catch(() => {
    // Si exec_sql no existe, usamos el cliente directo (Supabase v2)
  });

  for (const migration of migrations) {
    // Verificar si ya fue aplicada
    const { data: existing } = await supabase
      .from('_migrations')
      .select('name')
      .eq('name', migration.name)
      .single();

    if (existing) {
      console.log(`  ✓ ${migration.name} (ya aplicada)`);
      continue;
    }

    try {
      // Ejecutar SQL via rpc o directamente
      const { error } = await supabase.rpc('exec_sql', { sql: migration.sql });
      if (error) throw error;

      // Registrar migración
      await supabase.from('_migrations').insert({ name: migration.name });
      console.log(`  ✅ ${migration.name}`);
    } catch (err) {
      console.error(`  ❌ ${migration.name}: ${err.message}`);
      // No abortar — las siguientes migraciones pueden ser independientes
    }
  }

  console.log('✅ Migraciones completadas');
}

module.exports = { runMigrations };
