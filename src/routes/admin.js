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
    if (from)     { conditions.push(`received_at >= $${i++}`);  values.push(from); }
    if (to)       { conditions.push(`received_at <= $${i++}`);  values.push(to); }
    if (search)   {
      conditions.push(`(action ILIKE $${i} OR target ILIKE $${i} OR username ILIKE $${i})`);
      values.push(`%${search}%`); i++;
    }

    const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';

    const [rows, total] = await Promise.all([
      query(
        `SELECT id, action, target, before_data, after_data,
                user_id, username, role, ip, received_at
         FROM public.audit_log
         ${where}
         ORDER BY received_at DESC
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
const AUTO_PURGE_DAYS  = parseInt(process.env.GPS_RETENTION_DAYS || '2', 10);
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

/* ── GET /admin/gps-events/:plate ───────────────────────────── */
// Historial de eventos recibidos y respuestas de integraciones para una patente
router.get('/gps-events/:plate', requireRole('admin'), async (req, res) => {
  try {
    const { plate }  = req.params;
    const limit      = Math.min(parseInt(req.query.limit  || '50',  10), 200);
    const offset     = parseInt(req.query.offset || '0', 10);
    const dest_id    = req.query.dest_id || null;

    const conditions = ['e.plate = $1'];
    const values     = [plate.toUpperCase()];
    let   i          = 2;

    if (dest_id) {
      conditions.push(`e.destination_id = $${i++}`);
      values.push(dest_id);
    }

    const where = conditions.join(' AND ');

    const { rows } = await query(`
      SELECT
        e.id,
        e.plate,
        e.imei,
        e.lat,
        e.lon,
        e.speed,
        e.heading,
        e.ignition,
        e.wialon_ts,
        e.forward_ok,
        e.forward_resp,
        e.received_at,
        d.name  AS dest_name,
        d.id    AS dest_id
      FROM public.gps_events e
      LEFT JOIN public.destinations d ON d.id = e.destination_id
      WHERE ${where}
      ORDER BY e.received_at DESC
      LIMIT $${i++} OFFSET $${i++}
    `, [...values, limit, offset]);

    // Total para paginación
    const { rows: countRows } = await query(
      `SELECT COUNT(*) FROM public.gps_events e WHERE ${where}`,
      values
    );

    res.json({
      plate:  plate.toUpperCase(),
      total:  parseInt(countRows[0].count),
      limit,
      offset,
      events: rows,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* ── GET /admin/gps-events/:plate/destinations ───────────────── */
// Destinos únicos que han recibido eventos de una patente (para filtrar)
router.get('/gps-events/:plate/destinations', requireRole('admin'), async (req, res) => {
  try {
    const { plate } = req.params;
    const { rows } = await query(`
      SELECT DISTINCT d.id, d.name
      FROM public.gps_events e
      JOIN public.destinations d ON d.id = e.destination_id
      WHERE e.plate = $1
      ORDER BY d.name
    `, [plate.toUpperCase()]);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


/* ── GET /admin/samtech-sample/:plate ────────────────────────── */
router.get('/samtech-sample/:plate', requireRole('admin'), async (req, res) => {
  const { plate } = req.params;
  const dest_id = req.query.dest_id || null;

  try {
    // Buscar último evento con coords válidas
    const { rows } = await query(`
      SELECT e.imei, e.lat, e.lon, e.speed, e.heading, e.ignition,
             e.wialon_ts, u.name, u.rut
      FROM public.gps_events e
      JOIN public.units u ON u.imei = e.imei
      WHERE UPPER(e.plate) = UPPER($1)
        AND e.lat != 0 AND e.lon != 0
      ORDER BY e.received_at DESC LIMIT 1
    `, [plate]);

    if (!rows.length) return res.status(404).json({ error: 'Sin eventos GPS para esa patente.' });

    const r = rows[0];
    const ign = r.ignition === true || r.ignition === 1 ? 1 : 0;

    // Leer config del destino si se pasa dest_id
    let empresa = process.env.dduarte_EMPRESA || 'dduarte';
    let pgps    = process.env.dduarte_PGPS    || 'SigueloGPS';
    let login   = process.env.dduarte_USER    || '';
    let clave   = process.env.dduarte_PASS    || '';

    if (dest_id) {
      const { rows: dRows } = await query(
        'SELECT field_schema FROM public.destinations WHERE id = $1', [dest_id]
      );
      if (dRows.length) {
        let schema = dRows[0].field_schema;
        if (typeof schema === 'string') schema = JSON.parse(schema);
        for (const f of (schema || [])) {
          if (f.source === 'fixed' && f.fixedValue) {
            if (f.apiKey === 'samtech_empresa') empresa = f.fixedValue;
            if (f.apiKey === 'samtech_pgps')    pgps    = f.fixedValue;
            if (f.apiKey === 'samtech_login')   login   = f.fixedValue;
            if (f.apiKey === 'samtech_clave')   clave   = f.fixedValue;
          }
        }
      }
    }

    const p = n => String(n).padStart(2, '0');
    const d = r.wialon_ts ? new Date(r.wialon_ts) : new Date();
    const fn = `${p(d.getUTCDate())}/${p(d.getUTCMonth()+1)}/${d.getUTCFullYear()} ${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())}`;
    const pat = plate.toUpperCase().replace(/[^A-Z0-9]/g, '');

    const innerXml = `<?xml version="1.0" encoding="ISO-8859-1"?><datos><movil>` +
      `<pgps>${pgps}</pgps><empresa>${empresa}</empresa><tercero>${r.name || 'No Asignado'}</tercero>` +
      `<pat>${pat}</pat><fn>${fn}</fn>` +
      `<lat>${parseFloat(r.lat).toFixed(6)}</lat><lon>${parseFloat(r.lon).toFixed(6)}</lon>` +
      `<ori>${Math.round(Number(r.heading) || 0)}</ori><vel>${Math.round(Number(r.speed) || 0)}</vel>` +
      `<mot>${ign}</mot><hdop>000</hdop><odo>0</odo><eve>${ign ? 46 : 47}</eve>` +
      `<conductor>No Asignado</conductor><numSAT>0</numSAT><sens1>0</sens1><sens2>0</sens2>` +
      `</movil><usuario xmlns="user"><login>${login}</login><clave>********</clave></usuario></datos>`;

    const envelope = `<?xml version="1.0" encoding="utf-8"?>` +
      `<soap12:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ` +
      `xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap12="http://www.w3.org/2003/05/soap-envelope">` +
      `<soap12:Body><Post_XML xmlns="samtechpos"><xmldoc><![CDATA[${innerXml}]]></xmldoc></Post_XML>` +
      `</soap12:Body></soap12:Envelope>`;

    res.json({
      plate: pat,
      imei: r.imei,
      url: process.env.dduarte_URL || 'https://wspos.samtech.cl/WSP.asmx',
      soapAction: 'samtechpos/Post_XML',
      contentType: 'application/soap+xml; charset=utf-8; action="samtechpos/Post_XML"',
      empresa,
      pgps,
      fecha_utc: fn,
      lat: parseFloat(r.lat),
      lon: parseFloat(r.lon),
      innerXml,
      envelope,
      nota: 'La clave se muestra como ********. El XML real incluye la clave configurada.',
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Arranque diferido: espera 5 minutos para no competir con el inicio del servidor
// Solo activo si GPS_AUTO_PURGE !== 'false'
if (process.env.GPS_AUTO_PURGE !== 'false') {
  setTimeout(() => {
    runAutoPurge();
    setInterval(runAutoPurge, AUTO_PURGE_INTERVAL_MS);
  }, 5 * 60 * 1000); // 5 minutos — da tiempo para que el pool se estabilice
} else {
  console.log('[auto-purge] deshabilitado (GPS_AUTO_PURGE=false)');
}

module.exports = router;
