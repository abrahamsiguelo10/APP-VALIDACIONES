// src/routes/destinations.js
// CRUD de destinos GPS. Incluye auth y driver_slug (cols 013 y 012).

const express = require('express');
const router  = express.Router();
const { createClient } = require('@supabase/supabase-js');
const { requireAuth } = require('../middleware/auth');

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

// ── GET /destinations ─────────────────────────────────────────
// Devuelve todos los destinos incluyendo auth y driver_slug.
// El tcp-server los usa en forwardToDestinations().
router.get('/', requireAuth, async (req, res) => {
  const { data, error } = await supabase
    .from('destinations')
    .select('id, name, enabled, api_url, color, field_schema, driver_slug, auth, created_at, updated_at')
    .order('name');

  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// ── POST /destinations ────────────────────────────────────────
router.post('/', requireAuth, async (req, res) => {
  const { id, name, api_url, color, field_schema, driver_slug, auth } = req.body;

  if (!name) return res.status(400).json({ error: 'name es requerido' });

  const payload = {
    id:           id || undefined,          // Si el cliente provee id custom lo usa
    name:         name.trim(),
    api_url:      api_url?.trim() || null,
    color:        color || '#38bdf8',
    field_schema: field_schema || [],
    driver_slug:  driver_slug?.trim() || null,
    auth:         auth || null,
    enabled:      true,
  };

  const { data, error } = await supabase
    .from('destinations')
    .insert(payload)
    .select()
    .single();

  if (error) return res.status(500).json({ error: error.message });
  res.status(201).json(data);
});

// ── PATCH /destinations/:id ───────────────────────────────────
router.patch('/:id', requireAuth, async (req, res) => {
  const { id } = req.params;
  const { name, api_url, color, field_schema, driver_slug, auth } = req.body;

  const updates = {};
  if (name        !== undefined) updates.name         = name.trim();
  if (api_url     !== undefined) updates.api_url      = api_url?.trim() || null;
  if (color       !== undefined) updates.color        = color;
  if (field_schema !== undefined) updates.field_schema = field_schema;
  if (driver_slug !== undefined) updates.driver_slug  = driver_slug?.trim() || null;
  if (auth        !== undefined) updates.auth         = auth;   // null = sin auth
  updates.updated_at = new Date().toISOString();

  const { data, error } = await supabase
    .from('destinations')
    .update(updates)
    .eq('id', id)
    .select()
    .single();

  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// ── PATCH /destinations/:id/toggle ───────────────────────────
router.patch('/:id/toggle', requireAuth, async (req, res) => {
  // Leer estado actual
  const { data: current, error: fetchErr } = await supabase
    .from('destinations')
    .select('enabled')
    .eq('id', req.params.id)
    .single();

  if (fetchErr) return res.status(404).json({ error: 'Destino no encontrado' });

  const { data, error } = await supabase
    .from('destinations')
    .update({ enabled: !current.enabled, updated_at: new Date().toISOString() })
    .eq('id', req.params.id)
    .select()
    .single();

  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// ── DELETE /destinations/:id ──────────────────────────────────
router.delete('/:id', requireAuth, async (req, res) => {
  // Primero eliminar asignaciones en unit_destinations
  await supabase
    .from('unit_destinations')
    .delete()
    .eq('destination_id', req.params.id);

  const { error } = await supabase
    .from('destinations')
    .delete()
    .eq('id', req.params.id);

  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

module.exports = router;
