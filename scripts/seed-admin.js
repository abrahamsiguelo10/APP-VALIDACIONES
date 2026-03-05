/**
 * scripts/seed-admin.js
 * Crea el primer usuario admin en la BD.
 *
 * Uso:
 *   node scripts/seed-admin.js
 *
 * Variables requeridas en .env:
 *   DATABASE_URL, y opcionalmente ADMIN_USER / ADMIN_PASS
 */

require('dotenv').config();
const bcrypt = require('bcrypt');
const { query, pool } = require('../src/db/pool');

async function seed() {
  const username = process.env.ADMIN_USER || 'admin';
  const password = process.env.ADMIN_PASS || 'admin1234';

  console.log(`Creando usuario admin: "${username}"`);

  const hash = await bcrypt.hash(password, 12);

  try {
    const { rows } = await query(
      `INSERT INTO public.users (username, password_hash, role)
       VALUES ($1, $2, 'admin')
       ON CONFLICT (username) DO UPDATE
         SET password_hash = EXCLUDED.password_hash,
             role = 'admin',
             enabled = true
       RETURNING id, username, role`,
      [username, hash]
    );
    console.log('✓ Usuario creado/actualizado:', rows[0]);
    console.log(`  → Login: ${username} / ${password}`);
    console.log('  ⚠ Cambia la contraseña en el panel después del primer login.');
  } catch (err) {
    console.error('Error:', err.message);
  } finally {
    await pool.end();
  }
}

seed();
