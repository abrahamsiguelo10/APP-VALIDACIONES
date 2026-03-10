/**
 * src/routes/certificados.js
 */
const router = require('express').Router();
const { query } = require('../db/pool');
const { requireAuth, requireRole } = require('../middleware/auth');

/* POST /certificados — registrar al emitir */
router.post('/', requireAuth, async (req, res) => {
  try {
    const { id, patente, imei, empresa, rut_empresa, firmante, rut_firmante,
            fecha_emision, fecha_vencimiento, validez_texto } = req.body;
    if (!patente || !imei || !fecha_emision || !fecha_vencimiento)
      return res.status(400).json({ error: 'Faltan campos obligatorios.' });
    const emitido_por = req.user?.username || req.user?.sub || 'sistema';
    const q = id
      ? `INSERT INTO public.certificados
           (id,patente,imei,empresa,rut_empresa,firmante,rut_firmante,fecha_emision,fecha_vencimiento,validez_texto,emitido_por)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
         ON CONFLICT (id) DO NOTHING RETURNING *`
      : `INSERT INTO public.certificados
           (patente,imei,empresa,rut_empresa,firmante,rut_firmante,fecha_emision,fecha_vencimiento,validez_texto,emitido_por)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *`;
    const v = id
      ? [id,patente,imei,empresa||null,rut_empresa||null,firmante||null,rut_firmante||null,fecha_emision,fecha_vencimiento,validez_texto||null,emitido_por]
      : [patente,imei,empresa||null,rut_empresa||null,firmante||null,rut_firmante||null,fecha_emision,fecha_vencimiento,validez_texto||null,emitido_por];
    const { rows } = await query(q, v);
    res.status(201).json(rows[0] || { id });
  } catch (err) {
    console.error('[cert POST]', err);
    res.status(500).json({ error: 'Error al registrar certificado.' });
  }
});

/* GET /certificados — listar (admin) */
router.get('/', requireAuth, requireRole('admin'), async (req, res) => {
  try {
    const { rows } = await query(`SELECT * FROM public.certificados ORDER BY created_at DESC LIMIT 500`);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Error.' });
  }
});

/* GET /certificados/:id — verificación PÚBLICA */
router.get('/:id', async (req, res) => {
  try {
    const { rows } = await query(`SELECT * FROM public.certificados WHERE id = $1`, [req.params.id]);
    if (!rows.length) return res.status(404).json({ encontrado: false, mensaje: 'Certificado no encontrado.' });
    const c = rows[0];
    let estado = c.estado;
    if (estado === 'vigente' && new Date(c.fecha_vencimiento) < new Date()) estado = 'vencido';
    res.json({ encontrado:true, id:c.id, patente:c.patente, imei:c.imei, empresa:c.empresa,
      rut_empresa:c.rut_empresa, firmante:c.firmante, fecha_emision:c.fecha_emision,
      fecha_vencimiento:c.fecha_vencimiento, validez_texto:c.validez_texto, estado,
      invalidado_por:c.invalidado_por||null, invalidado_at:c.invalidado_at||null,
      emitido_por:c.emitido_por, created_at:c.created_at });
  } catch (err) {
    res.status(500).json({ error: 'Error al verificar.' });
  }
});

/* PATCH /certificados/:id/invalidar — solo admin */
router.patch('/:id/invalidar', requireAuth, requireRole('admin'), async (req, res) => {
  try {
    const invalidado_por = req.user?.username || req.user?.sub || 'admin';
    const { rows } = await query(
      `UPDATE public.certificados SET estado='invalidado', invalidado_por=$1, invalidado_at=now()
       WHERE id=$2 AND estado!='invalidado' RETURNING *`,
      [invalidado_por, req.params.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'No encontrado o ya invalidado.' });
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Error al invalidar.' });
  }
});

/* PATCH /certificados/:id/revalidar — solo admin */
router.patch('/:id/revalidar', requireAuth, requireRole('admin'), async (req, res) => {
  try {
    const { rows } = await query(
      `UPDATE public.certificados
       SET estado = 'vigente', invalidado_por = NULL, invalidado_at = NULL
       WHERE id = $1 AND estado = 'invalidado'
       RETURNING *`,
      [req.params.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'No encontrado o no está invalidado.' });
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Error al revalidar.' });
  }
});

module.exports = router;
