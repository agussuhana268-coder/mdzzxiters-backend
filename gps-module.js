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

  // Android calls this when location tracking consent is given
  app.post('/api/location/consent', commandLimiter, async (req, res) => {
    try {
      const auth = await authenticateDevice(req, res);
      if (!auth) return;
      const isConsent = req.body?.consent === true || req.body?.consent === 'true';

      const now = new Date().toISOString();
      const row = {
        license_key: auth.key,
        device_id: auth.deviceId,
        consent_status: isConsent ? 'GRANTED' : 'REVOKED',
        consented_at: isConsent ? now : null,
        revoked_at: isConsent ? null : now,
        updated_at: now
      };
      const { error } = await supabaseAdmin
        .from('gps_consents')
        .upsert(row, { onConflict: 'license_key,device_id' });
      if (error) return dbFailure(res, 'consent upsert failed', error);

      if (!isConsent) {
        await supabaseAdmin.from('gps_tracking_sessions')
          .update({ status: 'STOPPED', stopped_at: now, updated_at: now })
          .eq('license_key', auth.key)
          .eq('device_id', auth.deviceId)
          .eq('status', 'ACTIVE');
      }

      return res.json({
        success: true,
        consent_status: row.consent_status,
        message: isConsent ? 'Persetujuan berbagi lokasi tercatat' : 'Persetujuan dicabut'
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
      const trackingSessionId = clean(req.body?.tracking_session_id || ('session_' + auth.deviceId), 100);
      const provider = clean(req.body?.provider || 'unknown', 40);
      const deviceModel = clean(req.body?.device_model || 'Android Device', 120);
      const recordedAt = req.body?.timestamp ? new Date(req.body.timestamp) : new Date();

      if (!Number.isFinite(latitude) || latitude < -90 || latitude > 90 ||
          !Number.isFinite(longitude) || longitude < -180 || longitude > 180 ||
          !Number.isFinite(accuracy) || accuracy < 0 ||
          (altitude !== null && !Number.isFinite(altitude))) {
        return res.status(400).json({ success: false, code: 'invalid_location_payload' });
      }

      const { data: consent, error: consentError } = await supabaseAdmin.from('gps_consents')
        .select('consent_status')
        .eq('license_key', auth.key).eq('device_id', auth.deviceId).maybeSingle();
      if (consentError) return dbFailure(res, 'location consent lookup failed', consentError);
      if (!consent || consent.consent_status !== 'GRANTED') {
        return res.status(403).json({ success: false, code: 'USER_CONSENT_REQUIRED' });
      }

      const now = new Date().toISOString();
      const { error: sessionError } = await supabaseAdmin.from('gps_tracking_sessions').upsert({
        tracking_session_id: trackingSessionId,
        license_key: auth.key,
        device_id: auth.deviceId,
        status: 'ACTIVE',
        started_at: now,
        stopped_at: null,
        updated_at: now
      }, { onConflict: 'tracking_session_id' });
      if (sessionError) return dbFailure(res, 'tracking session upsert failed', sessionError);

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
      const trackingSessionId = clean(req.body?.tracking_session_id || ('session_' + auth.deviceId), 100);
      const allowed = new Set(['ACCEPTED', 'REJECTED', 'COMPLETED', 'EXECUTED', 'FAILED']);
      if (!commandId || !allowed.has(status))
        return res.status(400).json({ success: false, code: 'invalid_ack' });

      const { data: command, error: commandError } = await supabaseAdmin
        .from('gps_commands')
        .select('command_id,command,status')
        .eq('command_id', commandId)
        .eq('license_key', auth.key)
        .eq('device_id', auth.deviceId)
        .eq('status', 'PENDING')
        .maybeSingle();
      if (commandError) return dbFailure(res, 'command lookup failed', commandError);
      if (!command) return res.status(404).json({ success: false, code: 'command_not_found' });

      if (command.command === 'START_TRACKING') {
        const { data: consent, error: consentError } = await supabaseAdmin.from('gps_consents')
          .select('consent_status')
          .eq('license_key', auth.key).eq('device_id', auth.deviceId).maybeSingle();
        if (consentError) return dbFailure(res, 'command ACK consent lookup failed', consentError);
        if (!consent || consent.consent_status !== 'GRANTED') {
          return res.status(403).json({ success: false, code: 'USER_CONSENT_REQUIRED' });
        }
        const now = new Date().toISOString();
        await supabaseAdmin.from('gps_tracking_sessions').upsert({
          tracking_session_id: trackingSessionId,
          license_key: auth.key,
          device_id: auth.deviceId,
          status: 'ACTIVE',
          started_at: now,
          updated_at: now
        }, { onConflict: 'tracking_session_id' });
      }

      if (command && command.command === 'STOP_TRACKING') {
        const now = new Date().toISOString();
        await supabaseAdmin.from('gps_tracking_sessions')
          .update({ status: 'STOPPED', stopped_at: now, updated_at: now })
          .eq('license_key', auth.key)
          .eq('device_id', auth.deviceId);
      }

      const dbStatus = ['ACCEPTED', 'COMPLETED', 'EXECUTED'].includes(status) ? 'COMPLETED' : status;
      const { error: updateError } = await supabaseAdmin.from('gps_commands')
        .update({ status: dbStatus, acknowledged_at: new Date().toISOString() })
        .eq('command_id', commandId);
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
      const sessionId = clean(req.body?.tracking_session_id || ('session_' + auth.deviceId), 100);
      const isTracking = req.body?.is_tracking;
      if (typeof isTracking !== 'boolean')
        return res.status(400).json({ success: false, code: 'invalid_status_payload' });

      if (isTracking) {
        const { data: consent, error: consentError } = await supabaseAdmin.from('gps_consents')
          .select('consent_status')
          .eq('license_key', auth.key).eq('device_id', auth.deviceId).maybeSingle();
        if (consentError) return dbFailure(res, 'status consent lookup failed', consentError);
        if (!consent || consent.consent_status !== 'GRANTED') {
          return res.status(403).json({ success: false, code: 'USER_CONSENT_REQUIRED' });
        }
      }

      const now = new Date().toISOString();
      const { error } = await supabaseAdmin.from('gps_tracking_sessions')
        .upsert({
          tracking_session_id: sessionId,
          license_key: auth.key,
          device_id: auth.deviceId,
          status: isTracking ? 'ACTIVE' : 'STOPPED',
          updated_at: now,
          ...(isTracking ? { started_at: now } : { stopped_at: now })
        }, { onConflict: 'tracking_session_id' });

      if (error) return dbFailure(res, 'status update failed', error);
      return res.json({ success: true, status: isTracking ? 'ACTIVE' : 'STOPPED' });
    } catch (error) {
      return dbFailure(res, 'status update failed', error);
    }
  });

  // Admin endpoints
  app.get('/api/admin/location/devices', requireFirebaseAdmin, async (_req, res) => {
    try {
      const { data: licenses, error } = await supabaseAdmin
        .from('licenses')
        .select('key,nexus_id,device_id,active,expires_at,status')
        .limit(200);

      if (error) return dbFailure(res, 'admin devices query failed', error);

      const [{ data: sessions, error: sessionsError }, { data: consents, error: consentsError }] = await Promise.all([
        supabaseAdmin.from('gps_tracking_sessions')
          .select('tracking_session_id,license_key,device_id,status,started_at,stopped_at,updated_at')
          .order('updated_at', { ascending: false }),
        supabaseAdmin.from('gps_consents')
          .select('license_key,device_id,consent_status,consented_at,revoked_at')
      ]);
      if (sessionsError) return dbFailure(res, 'admin session list failed', sessionsError);
      if (consentsError) return dbFailure(res, 'admin consent list failed', consentsError);

      const sessionMap = new Map();
      (sessions || []).forEach(s => {
        const k = String(s.license_key) + '|' + String(s.device_id);
        if (!sessionMap.has(k)) sessionMap.set(k, s);
      });
      const consentMap = new Map((consents || []).map(c => [String(c.license_key) + '|' + String(c.device_id), c]));
      const devices = (licenses || []).map(l => {
        const deviceId = l.device_id || l.key;
        const mapKey = String(l.key) + '|' + String(deviceId);
        const session = sessionMap.get(mapKey) || null;
        const consent = consentMap.get(mapKey) || null;
        return {
          device_id: deviceId,
          key: l.key,
          nexus_id: l.nexus_id || 'NEXUS',
          active: l.active,
          expires_at: l.expires_at,
          tracking_status: session ? session.status : 'NOT_STARTED',
          tracking_session_id: session?.tracking_session_id || null,
          tracking_updated_at: session?.updated_at || null,
          consent_status: consent?.consent_status || 'NOT_GRANTED'
        };
      });

      return res.json({ success: true, devices });
    } catch (error) {
      return dbFailure(res, 'admin devices query failed', error);
    }
  });

  app.get('/api/admin/location/status/:device_id', requireFirebaseAdmin, async (req, res) => {
    try {
      const input = clean(req.params.device_id, 300);
      const { data: license, error: licenseError } = await supabaseAdmin.from('licenses')
        .select('key,device_id,active,expires_at')
        .or('key.eq.' + input.toUpperCase() + ',device_id.eq.' + input)
        .limit(1).maybeSingle();
      if (licenseError) return dbFailure(res, 'admin status license lookup failed', licenseError);
      if (!license) return res.status(404).json({ success: false, code: 'device_not_found' });

      const deviceId = license.device_id || input;
      const [{ data: session, error: sessionError }, { data: consent, error: consentError }, { data: latest, error: locationError }] = await Promise.all([
        supabaseAdmin.from('gps_tracking_sessions')
          .select('tracking_session_id,status,started_at,stopped_at,updated_at')
          .eq('license_key', license.key).eq('device_id', deviceId)
          .order('updated_at', { ascending: false }).limit(1).maybeSingle(),
        supabaseAdmin.from('gps_consents')
          .select('consent_status,consented_at,revoked_at')
          .eq('license_key', license.key).eq('device_id', deviceId).maybeSingle(),
        supabaseAdmin.from('gps_locations')
          .select('recorded_at,latitude,longitude,accuracy,provider,device_model')
          .eq('license_key', license.key).eq('device_id', deviceId)
          .order('recorded_at', { ascending: false }).limit(1).maybeSingle()
      ]);
      if (sessionError) return dbFailure(res, 'admin status session lookup failed', sessionError);
      if (consentError) return dbFailure(res, 'admin status consent lookup failed', consentError);
      if (locationError) return dbFailure(res, 'admin status location lookup failed', locationError);

      const lastLocationAt = latest?.recorded_at || null;
      const ageMs = lastLocationAt ? Date.now() - new Date(lastLocationAt).getTime() : null;
      const status = session?.status === 'ACTIVE'
        ? (ageMs !== null && ageMs > 120000 ? 'STALE' : 'ACTIVE')
        : (session?.status || 'NOT_STARTED');

      return res.json({
        success: true,
        device_id: deviceId,
        license_key: license.key,
        tracking_status: status,
        session: session || null,
        consent_status: consent?.consent_status || 'NOT_GRANTED',
        latest_location: latest || null
      });
    } catch (error) {
      return dbFailure(res, 'admin status lookup failed', error);
    }
  });

  app.get('/api/admin/location/latest/:device_id', requireFirebaseAdmin, async (req, res) => {
    try {
      const deviceId = clean(req.params.device_id, 300);
      const { data, error } = await supabaseAdmin.from('gps_locations')
        .select('device_id,license_key,nexus_id,latitude,longitude,accuracy,altitude,provider,device_model,recorded_at,tracking_session_id')
        .or(`device_id.eq.${deviceId},license_key.eq.${deviceId.toUpperCase()}`)
        .order('recorded_at', { ascending: false })
        .limit(1)
        .maybeSingle();

      if (error) return dbFailure(res, 'admin latest location query failed', error);
      if (!data) return res.status(404).json({ success: false, code: 'location_not_found', message: 'Belum ada data lokasi tercatat untuk perangkat/lisensi ini' });
      return res.json({ success: true, location: data });
    } catch (error) {
      return dbFailure(res, 'admin latest location query failed', error);
    }
  });

  app.get('/api/admin/location/history/:device_id', requireFirebaseAdmin, async (req, res) => {
    try {
      const deviceId = clean(req.params.device_id, 300);
      const limit = Math.max(1, Math.min(100, Number.parseInt(req.query.limit, 10) || 50));

      const { data, error } = await supabaseAdmin.from('gps_locations')
        .select('latitude,longitude,accuracy,altitude,provider,device_model,recorded_at,tracking_session_id')
        .or(`device_id.eq.${deviceId},license_key.eq.${deviceId.toUpperCase()}`)
        .order('recorded_at', { ascending: false })
        .limit(limit);

      if (error) return dbFailure(res, 'admin history query failed', error);
      return res.json({ success: true, history: data || [] });
    } catch (error) {
      return dbFailure(res, 'admin history query failed', error);
    }
  });

  // POST /api/admin/location/command: Supports lookup by BOTH License Key OR Device ID!
  app.post('/api/admin/location/command', requireFirebaseAdmin, async (req, res) => {
    try {
      const inputVal = clean(req.body?.device_id, 300);
      const command = clean(req.body?.command, 30).toUpperCase();

      if (!inputVal || !['START_TRACKING', 'STOP_TRACKING'].includes(command))
        return res.status(400).json({ success: false, code: 'invalid_command' });

      // Search license table by EITHER License Key OR Device ID!
      const { data: license, error: licenseError } = await supabaseAdmin
        .from('licenses')
        .select('key,active,expires_at,device_id,status')
        .or(`key.eq.${inputVal.toUpperCase()},device_id.eq.${inputVal}`)
        .limit(1)
        .maybeSingle();

      if (licenseError) return dbFailure(res, 'admin license lookup failed', licenseError);

      // Target key and target device ID
      const targetKey = license ? license.key : inputVal.toUpperCase();
      const targetDeviceId = (license && license.device_id) ? license.device_id : inputVal;

      const now = new Date().toISOString();
      if (command === 'START_TRACKING') {
        const { data: consent, error: consentError } = await supabaseAdmin.from('gps_consents')
          .select('consent_status')
          .eq('license_key', targetKey)
          .eq('device_id', targetDeviceId)
          .maybeSingle();
        if (consentError) return dbFailure(res, 'admin command consent check failed', consentError);
        if (!consent || consent.consent_status !== 'GRANTED') {
          return res.status(409).json({
            success: false,
            code: 'USER_CONSENT_REQUIRED',
            message: 'Pengguna perangkat harus menyetujui berbagi lokasi dari aplikasi terlebih dahulu.'
          });
        }
      }

      const commandId = crypto.randomUUID ? crypto.randomUUID() : ('cmd_' + Date.now() + '_' + Math.random().toString(36).substring(2, 7));

      const { error } = await supabaseAdmin.from('gps_commands').insert({
        command_id: commandId,
        license_key: targetKey,
        device_id: targetDeviceId,
        command: command,
        status: 'PENDING',
        requested_by: req.verifiedAdmin?.username || req.verifiedAdmin?.uid || 'admin'
      });

      if (error) return dbFailure(res, 'admin command insert failed', error);
      return res.json({ success: true, command_id: commandId, status: 'PENDING', message: 'Perintah ' + command + ' berhasil didaftarkan' });
    } catch (error) {
      return dbFailure(res, 'admin command failed', error);
    }
  });
};
