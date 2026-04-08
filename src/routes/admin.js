/**
 * routes/admin.js
 */
const router = require('express').Router();
const { query, pool } = require('../db/pool');
const { requireAuth, requireRole } = require('../middleware/auth');

router.use(requireAuth);

/* ── GET /admin/system-info ──────────────────────────────────── */
router.get('/system-info', requireRole('admin'), async (_req, res) => {
  try {
    const [units, dests, users, events] = await Promise.all([
      query('SELECT COUNT(*) FROM public.units'),
      query('SELECT COUNT(*) FROM public.unit_destinations WHERE enabled = true'),
      query('SELECT COUNT(*) FROM public.users'),
      query('SELECT COUNT(*) FROM public.gps_events'),
    ]);
    res.json({
      units:  parseInt(units.rows[0].count),
      dests:  parseInt(dests.rows[0].count),
      users:  parseInt(users.rows[0].count),
      events: parseInt(events.rows[0].count),
      db:     'connected',
      uptime: Math.floor(process.uptime()),
      ts:     new Date().toISOString(),
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* ── GET /admin/audit ────────────────────────────────────────── */
router.get('/audit', requireRole('admin'), async (req, res) => {
  try {
    const {
      limit  = 100,
      offset = 0,
      action,
      username,
      from,
      to,
      search,
    } = req.query;

    const conditions = [];
    const values     = [];
    let   i          = 1;

    if (action)   { conditions.push(`action ILIKE $${i++}`);   values.push(`%${action}%`); }
    if (username) { conditions.push(`username ILIKE $${i++}`); values.push(`%${username}%`); }
    if (from)     { conditions.push(`created_at >= $${i++}`);  values.push(from); }
    if (to)       { conditions.push(`created_at <= $${i++}`);  values.push(to); }
    if (search)   {
      conditions.push(`(action ILIKE $${i} OR target ILIKE $${i} OR username ILIKE $${i})`);
      values.push(`%${search}%`); i++;
    }

    const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';

    const [rows, total] = await Promise.all([
      query(
        `SELECT id, action, target, before_data, after_data,
                user_id, username, role, ip, created_at
         FROM public.audit_log
         ${where}
         ORDER BY created_at DESC
         LIMIT $${i++} OFFSET $${i++}`,
        [...values, parseInt(limit), parseInt(offset)]
      ),
      query(`SELECT COUNT(*) FROM public.audit_log ${where}`, values),
    ]);

    res.json({
      rows:  rows.rows,
      total: parseInt(total.rows[0].count),
      limit: parseInt(limit),
      offset: parseInt(offset),
    });
  } catch (err) {
    if (err.message?.includes('column') && err.message?.includes('does not exist')) {
      return res.json({ rows: [], total: 0,
        limit:  parseInt(req.query.limit  || 100),
        offset: parseInt(req.query.offset || 0),
        warning: 'Migraciones pendientes.' });
    }
    res.status(500).json({ error: err.message });
  }
});

/* ── GET /admin/qmgps-sample — genera XML de ejemplo para QAnalytics ── */
router.get('/qmgps-sample', requireRole('admin'), async (_req, res) => {
  const url  = process.env.QMGPS_ENDPOINT || 'https://ww3.qanalytics.cl/gps_test/service.asmx';
  const user = process.env.QMGPS_USER     || 'WS_test';
  const soap = 'http://tempuri.org/WM_INS_REPORTE_CLASS';

  const xmlBody = `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
               xmlns:xsd="http://www.w3.org/2001/XMLSchema"
               xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <Authentication xmlns="http://tempuri.org/">
      <Usuario>${user}</Usuario>
      <Clave>**********</Clave>
    </Authentication>
  </soap:Header>
  <soap:Body>
    <WM_INS_REPORTE_CLASS xmlns="http://tempuri.org/">
      <Tabla>
        <Datos xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
          <ID_REG>865468051217506</ID_REG>
          <LATITUD>-32.841983</LATITUD>
          <LONGITUD>-71.215300</LONGITUD>
          <VELOCIDAD>60</VELOCIDAD>
          <SENTIDO>270</SENTIDO>
          <FH_DATO>31-03-2026 15:30:00</FH_DATO>
          <PLACA>STDY42</PLACA>
          <CANT_SATELITES>8</CANT_SATELITES>
          <HDOP>1</HDOP>
          <TEMP1>999</TEMP1>
          <TEMP2>999</TEMP2>
          <TEMP3>999</TEMP3>
          <SENSORA_1>999</SENSORA_1>
          <AP>-1</AP>
          <IGNICION>1</IGNICION>
          <PANICO>-1</PANICO>
          <SENSORD_1>-1</SENSORD_1>
          <TRANS>N/A</TRANS>
          <SENSORA_2 xsi:nil="true"/>
          <SENSORA_3 xsi:nil="true"/>
          <SENSORA_4 xsi:nil="true"/>
          <SENSORA_5 xsi:nil="true"/>
          <SENSORA_6 xsi:nil="true"/>
          <SENSORA_7 xsi:nil="true"/>
          <SENSORA_8 xsi:nil="true"/>
          <SENSORA_9 xsi:nil="true"/>
          <SENSORA_10 xsi:nil="true"/>
          <SENSORD_2 xsi:nil="true"/>
          <SENSORD_3 xsi:nil="true"/>
          <SENSORD_4 xsi:nil="true"/>
          <SENSORD_5 xsi:nil="true"/>
          <SENSORD_6 xsi:nil="true"/>
          <SENSORD_7 xsi:nil="true"/>
          <SENSORD_8 xsi:nil="true"/>
          <SENSORD_9 xsi:nil="true"/>
        </Datos>
      </Tabla>
    </WM_INS_REPORTE_CLASS>
  </soap:Body>
</soap:Envelope>`;

  res.json({
    url,
    method:      'POST',
    soapAction:  soap,
    headers: {
      'Content-Type': 'text/xml; charset=utf-8',
      'SOAPAction':   `"${soap}"`,
    },
    body: xmlBody,
    nota: 'La contraseña se muestra como ******. El XML real incluye la contraseña configurada en las variables de entorno.',
  });
});

/* ── POST /admin/test-token — prueba un token contra una URL externa ── */
router.post('/test-token', requireRole('admin'), async (req, res) => {
  const { url, token, payload } = req.body;
  if (!url || !token) return res.status(400).json({ error: 'url y token requeridos.' });

  const testPayload = payload || [{
    fechaHora: new Date().toISOString().slice(0,19).replace('T',' '),
    latitud: -32.8, longitud: -71.2,
    patente: 'TEST01', provider: 'siguelo_gps',
    imei: '000000000000001',
    evento: 42, velocidad: 0, heading: 0, ignicion: 0,
  }];

  try {
    const r = await fetch(url, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
      body:    JSON.stringify(testPayload),
      signal:  AbortSignal.timeout ? AbortSignal.timeout(10000) : undefined,
    });
    const body = await r.text().catch(() => '');
    res.json({ http_status: r.status, ok: r.ok, body: body.slice(0, 500) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* ── POST /admin/purge-gps-events ───────────────────────────── */
// Borra eventos de gps_events más viejos que N días en lotes
// Body: { days: 15, batch: 5000 } — ambos opcionales
router.post('/purge-gps-events', requireRole('admin'), async (req, res) => {
  const days    = Math.max(1,   Math.min(365,   parseInt(req.body?.days  ?? 15,   10)));
  const batchSz = Math.max(100, Math.min(10000, parseInt(req.body?.batch ?? 5000, 10)));

  let totalDeleted = 0;
  let iterations   = 0;
  const maxIter    = 500;

  console.log(`[purge] iniciando — días a conservar: ${days}, lote: ${batchSz}`);

  try {
    while (iterations < maxIter) {
      const { rowCount } = await pool.query(
        `DELETE FROM public.gps_events
         WHERE id IN (
           SELECT id FROM public.gps_events
           WHERE received_at < NOW() - ($1 || ' days')::INTERVAL
           LIMIT $2
         )`,
        [days, batchSz]
      );

      totalDeleted += rowCount;
      iterations++;
      console.log(`[purge] lote ${iterations}: ${rowCount} eliminadas (total: ${totalDeleted})`);

      if (rowCount === 0) break;
    }

    console.log(`[purge] ✅ completado — ${totalDeleted} eventos eliminados en ${iterations} lotes`);
    res.json({ ok: true, deleted: totalDeleted, iterations, days_kept: days });

  } catch (e) {
    console.error('[purge] ❌ error:', e.message);
    res.status(500).json({ error: e.message, deleted_so_far: totalDeleted });
  }
});

/* ── Auto-purge al arrancar el servidor ──────────────────────── */
// Se ejecuta 30 segundos después del arranque para no impactar el inicio
// y luego cada 24 horas automáticamente
const AUTO_PURGE_DAYS  = parseInt(process.env.GPS_RETENTION_DAYS || '15', 10);
const AUTO_PURGE_BATCH = 5000;
const AUTO_PURGE_INTERVAL_MS = 24 * 60 * 60 * 1000; // 24 horas

async function runAutoPurge() {
  let totalDeleted = 0;
  let iterations   = 0;
  console.log(`[auto-purge] iniciando — conservando últimos ${AUTO_PURGE_DAYS} días`);
  try {
    while (iterations < 500) {
      const { rowCount } = await pool.query(
        `DELETE FROM public.gps_events
         WHERE id IN (
           SELECT id FROM public.gps_events
           WHERE received_at < NOW() - ($1 || ' days')::INTERVAL
           LIMIT $2
         )`,
        [AUTO_PURGE_DAYS, AUTO_PURGE_BATCH]
      );
      totalDeleted += rowCount;
      iterations++;
      if (rowCount === 0) break;
    }
    if (totalDeleted > 0) {
      console.log(`[auto-purge] ✅ ${totalDeleted} eventos eliminados en ${iterations} lotes`);
    } else {
      console.log(`[auto-purge] ✅ nada que eliminar`);
    }
  } catch (e) {
    console.error('[auto-purge] ❌ error:', e.message);
  }
}

// Arranque diferido: espera 30s para no impactar el inicio del servidor
setTimeout(() => {
  runAutoPurge();
  // Repetir cada 24 horas
  setInterval(runAutoPurge, AUTO_PURGE_INTERVAL_MS);
}, 30 * 1000);

module.exports = router;
