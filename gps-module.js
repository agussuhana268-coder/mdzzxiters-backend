'use strict';

const crypto = require('crypto');
const rateLimit = require('express-rate-limit');

module.exports = function registerGpsRoutes({ app, supabaseAdmin, requireFirebaseAdmin }) {
  const locationLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 240,
    standardHeaders: true,
    legacyHeaders: false,
    message: { success: false, code: 'gps_rate_limited' }
  });
  const commandLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 180,
    standardHeaders: true,
    legacyHeaders: false,
    message: { success: false, code: 'gps_command_rate_limited' }
  });

  const clean = (value, max = 200) => {
    const text = String(value ?? '').trim();
    return text ? text.slice(0, max) : '';
  };
  const normalizeKey = value => clean(value, 200).toUpperCase();

  async function findValidLicense(key, deviceId) {
    const { data, error } = await supabaseAdmin
      .from('licenses')
      .select('key,active,expires_at,device_id,status')
      .eq('key', key)
      .maybeSingle();

    if (error) throw error;
    if (!data) return { ok: false, status: 403, code: 'license_invalid' };
    if (data.active === false || ['revoked', 'inactive'].includes(String(data.status || '').toLowerCase()))
      return { ok: false, status: 403, code: 'license_revoked' };
    if (data.expires_at) {
      const expiry = new Date(data.expires_at).getTime();
      if (Number.isFinite(expiry) && expiry <= Date.now())
        return { ok: false, status: 403, code: 'license_expired' };
    }
    if (data.device_id && String(data.device_id) !== deviceId)
      return { ok: false, status: 403, code: 'device_mismatch' };
    return { ok: true, license: data };
  }

  async function findConsent(key, deviceId) {
    const { data, error } = await supabaseAdmin
      .from('gps_consents')
      .select('consent_status,consented_at,revoked_at')
      .eq('license_key', key)
      .eq('device_id', deviceId)
      .maybeSingle();
    if (error) throw error;
    return data;
  }

  async function authenticateDevice(req, res) {
    const body = req.body || {};
    const key = normalizeKey(body.key || req.headers['x-license-key'] || req.query.key);
    const deviceId = clean(body.device_id || req.headers['x-device-id'] || req.query.device_id, 300);
    if (!key || !deviceId) {
      res.status(400).json({ success: false, code: 'invalid_input', message: 'key dan device_id wajib diisi' });
      return null;
    }
    const result = await findValidLicense(key, deviceId);
    if (!result.ok) {
      res.status(result.status).json({ success: false, code: result.code });
      return null;
    }
    return { key, deviceId, license: result.license };
  }

  function dbFailure(res, label, error) {
    console.error('[GPS]', label, error?.message || error);
    return res.status(503).json({
      success: false,
      code: 'gps_storage_unavailable',
      message: 'Penyimpanan GPS belum siap. Pastikan SQL migration GPS sudah dijalankan.'
    });
  }

  // Android calls this only after the user has explicitly accepted/revoked location sharing in the app.
  app.post('/api/location/consent', commandLimiter, async (req, res) => {
    try {
      const auth = await authenticateDevice(req, res);
      if (!auth) return;
      if (typeof req.body?.consent !== 'boolean')
        return res.status(400).json({ success: false, code: 'invalid_consent' });

      const now = new Date().toISOString();
      const row = {
        license_key: auth.key,
        device_id: auth.deviceId,
        consent_status: req.body.consent ? 'GRANTED' : 'REVOKED',
        consented_at: req.body.consent ? now : null,
        revoked_at: req.body.consent ? null : now,
        updated_at: now
      };
      const { error } = await supabaseAdmin
        .from('gps_consents')
        .upsert(row, { onConflict: 'license_key,device_id' });
      if (error) return dbFailure(res, 'consent upsert failed', error);

      if (!req.body.consent) {
        await supabaseAdmin.from('gps_tracking_sessions')
          .update({ status: 'STOPPED', stopped_at: now, updated_at: now })
          .eq('license_key', auth.key)
          .eq('device_id', auth.deviceId)
          .eq('status', 'ACTIVE');
      }

      return res.json({
        success: true,
        consent_status: row.consent_status,
        message: req.body.consent ? 'Persetujuan berbagi lokasi tercatat' : 'Persetujuan dicabut'
      });
    } catch (error) {
      return dbFailure(res, 'consent endpoint failed', error);
    }
  });

  app.post('/api/location/update', locationLimiter, async (req, res) => {
    try {
      const auth = await authenticateDevice(req, res);
      if (!auth) return;

      const latitude = Number(req.body?.latitude);
      const longitude = Number(req.body?.longitude);
      const accuracy = Number(req.body?.accuracy ?? 0);
      const altitude = req.body?.altitude == null ? null : Number(req.body.altitude);
      const trackingSessionId = clean(req.body?.tracking_session_id, 100);
      const provider = clean(req.body?.provider || 'unknown', 40);
      const deviceModel = clean(req.body?.device_model || 'Android Device', 120);
      const recordedAt = req.body?.timestamp ? new Date(req.body.timestamp) : new Date();

      if (!Number.isFinite(latitude) || latitude < -90 || latitude > 90 ||
          !Number.isFinite(longitude) || longitude < -180 || longitude > 180 ||
          !Number.isFinite(accuracy) || accuracy < 0 ||
          (altitude !== null && !Number.isFinite(altitude)) ||
          !trackingSessionId || !Number.isFinite(recordedAt.getTime()) ||
          recordedAt.getTime() > Date.now() + 5 * 60 * 1000 ||
          recordedAt.getTime() < Date.now() - 24 * 60 * 60 * 1000) {
        return res.status(400).json({ success: false, code: 'invalid_location_payload' });
      }

      const consent = await findConsent(auth.key, auth.deviceId);
      if (!consent || consent.consent_status !== 'GRANTED' || consent.revoked_at)
        return res.status(403).json({ success: false, code: 'gps_consent_required' });

      const { data: session, error: sessionError } = await supabaseAdmin
        .from('gps_tracking_sessions')
        .select('tracking_session_id,status')
        .eq('tracking_session_id', trackingSessionId)
        .eq('license_key', auth.key)
        .eq('device_id', auth.deviceId)
        .maybeSingle();
      if (sessionError) return dbFailure(res, 'tracking session lookup failed', sessionError);
      if (!session || session.status !== 'ACTIVE')
        return res.status(403).json({ success: false, code: 'gps_session_inactive' });

      const { error } = await supabaseAdmin.from('gps_locations').insert({
        license_key: auth.key,
        device_id: auth.deviceId,
        nexus_id: clean(req.body?.nexus_id, 120) || null,
        tracking_session_id: trackingSessionId,
        latitude,
        longitude,
        accuracy,
        altitude,
        provider,
        device_model: deviceModel,
        recorded_at: recordedAt.toISOString()
      });
      if (error) return dbFailure(res, 'location insert failed', error);

      return res.json({ success: true, message: 'Location recorded' });
    } catch (error) {
      return dbFailure(res, 'location update failed', error);
    }
  });

  app.get('/api/location/command', commandLimiter, async (req, res) => {
    try {
      const auth = await authenticateDevice(req, res);
      if (!auth) return;
      const { data, error } = await supabaseAdmin
        .from('gps_commands')
        .select('command_id,command,status,created_at')
        .eq('license_key', auth.key)
        .eq('device_id', auth.deviceId)
        .eq('status', 'PENDING')
        .order('created_at', { ascending: true })
        .limit(1)
        .maybeSingle();
      if (error) return dbFailure(res, 'command polling failed', error);
      if (!data) return res.json({ success: true, command: 'NONE' });

      if (data.command === 'START_TRACKING') {
        const consent = await findConsent(auth.key, auth.deviceId);
        if (!consent || consent.consent_status !== 'GRANTED' || consent.revoked_at)
          return res.status(403).json({ success: false, code: 'gps_consent_required' });
      }

      // Keep command pending until Android ACKs it; the Android client must process command_id idempotently.
      return res.json({
        success: true,
        command: data.command,
        command_id: data.command_id
      });
    } catch (error) {
      return dbFailure(res, 'command polling failed', error);
    }
  });

  app.post('/api/location/command/ack', commandLimiter, async (req, res) => {
    try {
      const auth = await authenticateDevice(req, res);
      if (!auth) return;
      const commandId = clean(req.body?.command_id, 100);
      const status = clean(req.body?.status, 20).toUpperCase();
      const trackingSessionId = clean(req.body?.tracking_session_id, 100);
      const allowed = new Set(['ACCEPTED', 'REJECTED', 'COMPLETED', 'FAILED']);
      if (!commandId || !allowed.has(status))
        return res.status(400).json({ success: false, code: 'invalid_ack' });

      const { data: command, error: commandError } = await supabaseAdmin
        .from('gps_commands')
        .select('command_id,command,status')
        .eq('command_id', commandId)
        .eq('license_key', auth.key)
        .eq('device_id', auth.deviceId)
        .maybeSingle();
      if (commandError) return dbFailure(res, 'command lookup failed', commandError);
      if (!command || !['PENDING', 'ACKNOWLEDGED'].includes(command.status))
        return res.status(404).json({ success: false, code: 'command_not_found_or_closed' });

      if (command.command === 'START_TRACKING' && status === 'ACCEPTED') {
        if (!trackingSessionId)
          return res.status(400).json({ success: false, code: 'tracking_session_id_required' });
        const consent = await findConsent(auth.key, auth.deviceId);
        if (!consent || consent.consent_status !== 'GRANTED' || consent.revoked_at)
          return res.status(403).json({ success: false, code: 'gps_consent_required' });
        const now = new Date().toISOString();
        const { error } = await supabaseAdmin.from('gps_tracking_sessions').upsert({
          tracking_session_id: trackingSessionId,
          license_key: auth.key,
          device_id: auth.deviceId,
          status: 'ACTIVE',
          started_at: now,
          stopped_at: null,
          updated_at: now
        }, { onConflict: 'tracking_session_id' });
        if (error) return dbFailure(res, 'tracking session create failed', error);
      }

      if (command.command === 'STOP_TRACKING' && ['ACCEPTED', 'COMPLETED'].includes(status)) {
        const now = new Date().toISOString();
        await supabaseAdmin.from('gps_tracking_sessions')
          .update({ status: 'STOPPED', stopped_at: now, updated_at: now })
          .eq('license_key', auth.key)
          .eq('device_id', auth.deviceId)
          .eq('status', 'ACTIVE');
      }

      const dbStatus = status === 'ACCEPTED' ? 'ACKNOWLEDGED' : status;
      const { error: updateError } = await supabaseAdmin.from('gps_commands')
        .update({ status: dbStatus, acknowledged_at: new Date().toISOString() })
        .eq('command_id', commandId)
        .eq('license_key', auth.key)
        .eq('device_id', auth.deviceId);
      if (updateError) return dbFailure(res, 'command ACK update failed', updateError);

      return res.json({ success: true, status: dbStatus });
    } catch (error) {
      return dbFailure(res, 'command ACK failed', error);
    }
  });

  app.post('/api/location/status', commandLimiter, async (req, res) => {
    try {
      const auth = await authenticateDevice(req, res);
      if (!auth) return;
      const sessionId = clean(req.body?.tracking_session_id, 100);
      const isTracking = req.body?.is_tracking;
      if (!sessionId || typeof isTracking !== 'boolean')
        return res.status(400).json({ success: false, code: 'invalid_status_payload' });

      if (isTracking) {
        const consent = await findConsent(auth.key, auth.deviceId);
        if (!consent || consent.consent_status !== 'GRANTED' || consent.revoked_at)
          return res.status(403).json({ success: false, code: 'gps_consent_required' });
      }

      const now = new Date().toISOString();
      const { error } = await supabaseAdmin.from('gps_tracking_sessions')
        .update({
          status: isTracking ? 'ACTIVE' : 'STOPPED',
          updated_at: now,
          ...(isTracking ? {} : { stopped_at: now })
        })
        .eq('tracking_session_id', sessionId)
        .eq('license_key', auth.key)
        .eq('device_id', auth.deviceId);
      if (error) return dbFailure(res, 'status update failed', error);
      return res.json({ success: true, status: isTracking ? 'ACTIVE' : 'STOPPED' });
    } catch (error) {
      return dbFailure(res, 'status update failed', error);
    }
  });

  // Admin endpoints use the existing Firebase/backend admin session middleware.
  app.get('/api/admin/location/devices', requireFirebaseAdmin, async (_req, res) => {
    try {
      const { data: consents, error } = await supabaseAdmin
        .from('gps_consents')
        .select('license_key,device_id,consent_status,consented_at,revoked_at')
        .eq('consent_status', 'GRANTED')
        .is('revoked_at', null)
        .limit(200);
      if (error) return dbFailure(res, 'admin devices query failed', error);
      const devices = [];
      for (const consent of (consents || [])) {
        const { data: session } = await supabaseAdmin
          .from('gps_tracking_sessions')
          .select('tracking_session_id,status,started_at,updated_at')
          .eq('license_key', consent.license_key)
          .eq('device_id', consent.device_id)
          .eq('status', 'ACTIVE')
          .order('started_at', { ascending: false })
          .limit(1)
          .maybeSingle();
        const { data: latest } = await supabaseAdmin
          .from('gps_locations')
          .select('latitude,longitude,accuracy,provider,device_model,recorded_at')
          .eq('license_key', consent.license_key)
          .eq('device_id', consent.device_id)
          .order('recorded_at', { ascending: false })
          .limit(1)
          .maybeSingle();
        devices.push({
          device_id: consent.device_id,
          license_key_masked: consent.license_key.slice(0, 4) + '••••' + consent.license_key.slice(-4),
          consent_status: consent.consent_status,
          tracking_status: session ? 'ACTIVE' : 'INACTIVE',
          tracking_session_id: session?.tracking_session_id || null,
          latest_location: latest || null
        });
      }
      return res.json({ success: true, devices });
    } catch (error) {
      return dbFailure(res, 'admin devices query failed', error);
    }
  });

  app.get('/api/admin/location/latest/:device_id', requireFirebaseAdmin, async (req, res) => {
    try {
      const deviceId = clean(req.params.device_id, 300);
      const { data: consent, error: consentError } = await supabaseAdmin
        .from('gps_consents')
        .select('license_key')
        .eq('device_id', deviceId)
        .eq('consent_status', 'GRANTED')
        .is('revoked_at', null)
        .limit(1)
        .maybeSingle();
      if (consentError) return dbFailure(res, 'admin consent lookup failed', consentError);
      if (!consent) return res.status(403).json({ success: false, code: 'gps_consent_not_active' });

      const { data, error } = await supabaseAdmin.from('gps_locations')
        .select('device_id,latitude,longitude,accuracy,altitude,provider,device_model,recorded_at,tracking_session_id')
        .eq('device_id', deviceId)
        .eq('license_key', consent.license_key)
        .order('recorded_at', { ascending: false })
        .limit(1)
        .maybeSingle();
      if (error) return dbFailure(res, 'admin latest location query failed', error);
      if (!data) return res.status(404).json({ success: false, code: 'location_not_found' });
      return res.json({ success: true, location: data });
    } catch (error) {
      return dbFailure(res, 'admin latest location query failed', error);
    }
  });

  app.get('/api/admin/location/history/:device_id', requireFirebaseAdmin, async (req, res) => {
    try {
      const deviceId = clean(req.params.device_id, 300);
      const limit = Math.max(1, Math.min(100, Number.parseInt(req.query.limit, 10) || 50));
      const { data: consent, error: consentError } = await supabaseAdmin
        .from('gps_consents')
        .select('license_key')
        .eq('device_id', deviceId)
        .eq('consent_status', 'GRANTED')
        .is('revoked_at', null)
        .limit(1)
        .maybeSingle();
      if (consentError) return dbFailure(res, 'admin history consent lookup failed', consentError);
      if (!consent) return res.status(403).json({ success: false, code: 'gps_consent_not_active' });

      const { data, error } = await supabaseAdmin.from('gps_locations')
        .select('latitude,longitude,accuracy,altitude,provider,device_model,recorded_at,tracking_session_id')
        .eq('device_id', deviceId)
        .eq('license_key', consent.license_key)
        .order('recorded_at', { ascending: false })
        .limit(limit);
      if (error) return dbFailure(res, 'admin history query failed', error);
      return res.json({ success: true, history: data || [] });
    } catch (error) {
      return dbFailure(res, 'admin history query failed', error);
    }
  });

  app.post('/api/admin/location/command', requireFirebaseAdmin, async (req, res) => {
    try {
      const deviceId = clean(req.body?.device_id, 300);
      const command = clean(req.body?.command, 30).toUpperCase();
      if (!deviceId || !['START_TRACKING', 'STOP_TRACKING'].includes(command))
        return res.status(400).json({ success: false, code: 'invalid_command' });

      const { data: license, error: licenseError } = await supabaseAdmin
        .from('licenses')
        .select('key,active,expires_at,device_id,status')
        .eq('device_id', deviceId)
        .limit(1)
        .maybeSingle();
      if (licenseError) return dbFailure(res, 'admin license lookup failed', licenseError);
      if (!license) return res.status(404).json({ success: false, code: 'device_license_not_found' });

      if (command === 'START_TRACKING') {
        const validation = await findValidLicense(license.key, deviceId);
        if (!validation.ok)
          return res.status(validation.status).json({ success: false, code: validation.code });
        const consent = await findConsent(license.key, deviceId);
        if (!consent || consent.consent_status !== 'GRANTED' || consent.revoked_at)
          return res.status(403).json({ success: false, code: 'gps_consent_required' });
      }

      const commandId = crypto.randomUUID();
      const { error } = await supabaseAdmin.from('gps_commands').insert({
        command_id: commandId,
        license_key: license.key,
        device_id: deviceId,
        command,
        status: 'PENDING',
        requested_by: req.verifiedAdmin?.username || req.verifiedAdmin?.uid || 'admin'
      });
      if (error) return dbFailure(res, 'admin command insert failed', error);
      return res.json({ success: true, command_id: commandId, status: 'PENDING' });
    } catch (error) {
      return dbFailure(res, 'admin command failed', error);
    }
  });
};
