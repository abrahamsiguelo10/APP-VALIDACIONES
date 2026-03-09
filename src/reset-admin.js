/**
 * reset-admin.js — Script de emergencia para resetear contraseña del admin
 * 
 * Uso:
 *   node src/reset-admin.js
 * 
 * ⚠️  Ejecutar UNA SOLA VEZ y luego eliminar este archivo del repo.
 */

require('dotenv').config();
const bcrypt     = require('bcrypt');
const { query }  = require('./db/pool');

const NEW_PASSWORD = '1234';
const USERNAME     = 'admin';

(async () => {
  try {
    console.log(`[reset-admin] Reseteando contraseña de "${USERNAME}"...`);

    const hash = await bcrypt.hash(NEW_PASSWORD, 10);

    const { rows } = await query(
      `UPDATE public.users
       SET password_hash = $1
       WHERE username = $2
       RETURNING id, username, role`,
      [hash, USERNAME]
    );

    if (rows.length === 0) {
      // No existe — crearlo
      console.log(`[reset-admin] Usuario no encontrado. Creando admin...`);
      const { rows: created } = await query(
        `INSERT INTO public.users (username, password_hash, role, enabled)
         VALUES ($1, $2, 'admin', true)
         ON CONFLICT (username) DO UPDATE SET password_hash = $2
         RETURNING id, username, role`,
        [USERNAME, hash]
      );
      console.log(`[reset-admin] ✓ Creado:`, created[0]);
    } else {
      console.log(`[reset-admin] ✓ Contraseña actualizada:`, rows[0]);
    }

    console.log(`[reset-admin] ✓ Login: usuario="${USERNAME}" contraseña="${NEW_PASSWORD}"`);
    process.exit(0);
  } catch (e) {
    console.error('[reset-admin] Error:', e.message);
    process.exit(1);
  }
})();
