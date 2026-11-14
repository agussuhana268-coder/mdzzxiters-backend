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
    const deviceId = clean(body.device_id || req.headers['x-device-id'] || req.query.device_id, 300).toLowerCase();
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
    const errCode = error?.code || 'db_error';
    const errMessage = error?.message ? String(error.message).slice(0, 120) : 'Unknown storage error';
    console.error('[GPS DB Failure]', label, 'Code:', errCode, 'Msg:', errMessage);
    return res.status(503).json({
      success: false,
      code: 'gps_storage_unavailable',
      db_code: errCode,
      message: `Penyimpanan GPS belum siap (${errCode}). Pastikan SQL migration GPS sudah dijalankan.`
    });
  }

  // POST /api/location/consent — Atomic RPC Execution (Zero Non-Atomic Fallback)
  app.post('/api/location/consent', commandLimiter, async (req, res) => {
    try {
      const auth = await authenticateDevice(req, res);
      if (!auth) return;

      const rawConsent = req.body?.consent;
      if (typeof rawConsent !== 'boolean' && rawConsent !== 'true' && rawConsent !== 'false' && rawConsent !== 'GRANTED' && rawConsent !== 'REVOKED') {
        return res.status(400).json({ success: false, code: 'invalid_consent_status', message: 'Consent must be boolean (true/false) or GRANTED/REVOKED' });
      }

      const isConsent = rawConsent === true || rawConsent === 'true' || rawConsent === 'GRANTED';
      const consentStatus = isConsent ? 'GRANTED' : 'REVOKED';

      const { data: rpcRes, error: rpcError } = await supabaseAdmin
        .rpc('nexus_record_gps_consent', {
          p_license_key: auth.key,
          p_device_id: auth.deviceId,
          p_consent_status: consentStatus
        });

      if (rpcError) return dbFailure(res, 'consent rpc execution failed', rpcError);

      if (!rpcRes || rpcRes.success !== true) {
        return res.status(403).json({
          success: false,
          code: rpcRes?.code || 'consent_rejected',
          message: rpcRes?.message || 'Persetujuan lokasi ditolak'
        });
      }

      if (!isConsent) {
        const now = new Date().toISOString();
        const { error: sessionStopError } = await supabaseAdmin.from('gps_tracking_sessions')
          .update({ status: 'STOPPED', stopped_at: now, updated_at: now })
          .eq('license_key', auth.key)
          .eq('device_id', auth.deviceId)
          .eq('status', 'ACTIVE');

        if (sessionStopError) {
          console.error('[GPS Consent Revoke Error]', 'Failed to stop tracking session:', sessionStopError.message);
          return dbFailure(res, 'failed to stop tracking session on revoke', sessionStopError);
        }
      }

      return res.json({
        success: true,
        consent_status: rpcRes.consent_status,
        message: rpcRes.message
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
      const batteryLevel = Number.isInteger(Number(req.body?.battery_level)) ? Number(req.body.battery_level) : 100;
      const isCharging = req.body?.is_charging === true || req.body?.is_charging === 'true';
      const recordedAt = req.body?.timestamp ? new Date(req.body.timestamp) : new Date();

      if (!Number.isFinite(latitude) || latitude < -90 || latitude > 90 ||
          !Number.isFinite(longitude) || longitude < -180 || longitude > 180 ||
          !Number.isFinite(accuracy) || accuracy < 0 ||
          (altitude !== null && !Number.isFinite(altitude))) {
        return res.status(400).json({ success: false, code: 'invalid_location_payload' });
      }

      const consent = await findConsent(auth.key, auth.deviceId);
      if (!consent || consent.consent_status !== 'GRANTED' || consent.revoked_at)
        return res.status(403).json({ success: false, code: 'gps_consent_required' });

      const now = new Date().toISOString();
      const { error: sessionError } = await supabaseAdmin.from('gps_tracking_sessions').upsert({
        tracking_session_id: trackingSessionId,
        license_key: auth.key,
        device_id: auth.deviceId,
        status: 'ACTIVE',
        started_at: now,
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
        battery_level: batteryLevel,
        is_charging: isCharging,
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

      return res.json({
        success: true,
        command: data.command,
        command_id: data.command_id
      });
    } catch (error) {
      return dbFailure(res, 'command polling failed', error);
    }
  });

  // POST /api/location/command/ack — Security Hardened ACK Handler
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
        .maybeSingle();

      if (commandError) return dbFailure(res, 'command lookup failed', commandError);
      if (!command) {
        return res.status(404).json({
          success: false,
          code: 'command_not_found',
          message: 'Perintah tidak ditemukan untuk perangkat dan lisensi ini'
        });
      }

      if (command.command === 'START_TRACKING' && ['ACCEPTED', 'COMPLETED', 'EXECUTED'].includes(status)) {
        const consent = await findConsent(auth.key, auth.deviceId);
        if (!consent || consent.consent_status !== 'GRANTED' || consent.revoked_at) {
          return res.status(403).json({
            success: false,
            code: 'gps_consent_required',
            message: 'GPS consent required before starting tracking session'
          });
        }

        const now = new Date().toISOString();
        const { error: sessionError } = await supabaseAdmin.from('gps_tracking_sessions').upsert({
          tracking_session_id: trackingSessionId,
          license_key: auth.key,
          device_id: auth.deviceId,
          status: 'ACTIVE',
          started_at: now,
          updated_at: now
        }, { onConflict: 'tracking_session_id' });

        if (sessionError) return dbFailure(res, 'tracking session activate failed', sessionError);
      }

      if (command.command === 'STOP_TRACKING' && ['ACCEPTED', 'COMPLETED', 'EXECUTED'].includes(status)) {
        const now = new Date().toISOString();
        const { error: sessionStopError } = await supabaseAdmin.from('gps_tracking_sessions')
          .update({ status: 'STOPPED', stopped_at: now, updated_at: now })
          .eq('license_key', auth.key)
          .eq('device_id', auth.deviceId);

        if (sessionStopError) return dbFailure(res, 'tracking session stop failed', sessionStopError);
      }

      const dbStatus = ['ACCEPTED', 'COMPLETED', 'EXECUTED'].includes(status) ? 'COMPLETED' : status;
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
      const sessionId = clean(req.body?.tracking_session_id || ('session_' + auth.deviceId), 100);
      const isTracking = req.body?.is_tracking;
      if (typeof isTracking !== 'boolean')
        return res.status(400).json({ success: false, code: 'invalid_status_payload' });

      const now = new Date().toISOString();
      const { error: statusError } = await supabaseAdmin.from('gps_tracking_sessions')
        .upsert({
          tracking_session_id: sessionId,
          license_key: auth.key,
          device_id: auth.deviceId,
          status: isTracking ? 'ACTIVE' : 'STOPPED',
          updated_at: now,
          ...(isTracking ? { started_at: now } : { stopped_at: now })
        }, { onConflict: 'tracking_session_id' });

      if (statusError) return dbFailure(res, 'status update failed', statusError);
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

      const devices = (licenses || []).map(l => ({
        device_id: l.device_id || l.key,
        key: l.key,
        nexus_id: l.nexus_id || 'NEXUS',
        active: l.active,
        expires_at: l.expires_at
      }));

      return res.json({ success: true, devices });
    } catch (error) {
      return dbFailure(res, 'admin devices query failed', error);
    }
  });

  app.get('/api/admin/location/latest/:device_id', requireFirebaseAdmin, async (req, res) => {
    try {
      const deviceId = clean(req.params.device_id, 300).toLowerCase();
      const { data, error } = await supabaseAdmin.from('gps_locations')
        .select('device_id,license_key,nexus_id,latitude,longitude,accuracy,altitude,provider,device_model,battery_level,is_charging,recorded_at,tracking_session_id')
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
      const deviceId = clean(req.params.device_id, 300).toLowerCase();
      const limit = Math.max(1, Math.min(100, Number.parseInt(req.query.limit, 10) || 50));

      const { data, error } = await supabaseAdmin.from('gps_locations')
        .select('latitude,longitude,accuracy,altitude,provider,device_model,battery_level,is_charging,recorded_at,tracking_session_id')
        .or(`device_id.eq.${deviceId},license_key.eq.${deviceId.toUpperCase()}`)
        .order('recorded_at', { ascending: false })
        .limit(limit);

      if (error) return dbFailure(res, 'admin history query failed', error);
      return res.json({ success: true, history: data || [] });
    } catch (error) {
      return dbFailure(res, 'admin history query failed', error);
    }
  });

  // POST /api/admin/location/command: STRICTLY REQUIRES EXPLICIT USER CONSENT! DO NOT AUTO-CREATE CONSENT!
  app.post('/api/admin/location/command', requireFirebaseAdmin, async (req, res) => {
    try {
      const inputVal = clean(req.body?.device_id, 300);
      const command = clean(req.body?.command, 30).toUpperCase();

      if (!inputVal || !['START_TRACKING', 'STOP_TRACKING'].includes(command))
        return res.status(400).json({ success: false, code: 'invalid_command' });

      const { data: license, error: licenseError } = await supabaseAdmin
        .from('licenses')
        .select('key,active,expires_at,device_id,status')
        .or(`key.eq.${inputVal.toUpperCase()},device_id.eq.${inputVal.toLowerCase()}`)
        .limit(1)
        .maybeSingle();

      if (licenseError) return dbFailure(res, 'admin license lookup failed', licenseError);
      if (!license) return res.status(404).json({ success: false, code: 'device_license_not_found', message: 'Lisensi atau perangkat tidak ditemukan' });

      const targetKey = license.key;
      const targetDeviceId = license.device_id || inputVal.toLowerCase();

      if (command === 'START_TRACKING') {
        const consent = await findConsent(targetKey, targetDeviceId);
        if (!consent || consent.consent_status !== 'GRANTED' || consent.revoked_at) {
          return res.status(403).json({
            success: false,
            code: 'gps_consent_required',
            message: 'Pengguna perangkat belum memberikan persetujuan berbagi lokasi (GPS Consent)'
          });
        }
      }

      const commandId = crypto.randomUUID ? crypto.randomUUID() : ('cmd_' + Date.now() + '_' + Math.random().toString(36).substring(2, 7));

      const { error } = await supabaseAdmin.from('gps_commands').insert({
        command_id: commandId,
        license_key: targetKey,
        device_id: targetDeviceId,
        command,
        status: 'PENDING',
        requested_by: req.verifiedAdmin?.username || req.verifiedAdmin?.uid || 'admin'
      });

      if (error) return dbFailure(res, 'admin command insert failed', error);
      return res.json({ success: true, command_id: commandId, status: 'PENDING', message: 'Perintah ' + command + ' berhasil didaftarkan' });
    } catch (error) {
      return dbFailure(res, 'admin command failed', error);
    }
  });

  // POST /api/admin/licenses/rebind — Security Hardened Owner-Only CAS Rebind Endpoint
  app.post('/api/admin/licenses/rebind', requireFirebaseAdmin, async (req, res) => {
    try {
      if (req.verifiedAdmin?.role !== 'owner') {
        return res.status(403).json({
          success: false,
          code: 'OWNER_ROLE_REQUIRED',
          message: 'Hanya akun Owner yang berwenang melakukan rebind lisensi'
        });
      }

      const key = clean(req.body?.key, 100).toUpperCase();
      const newDeviceId = clean(req.body?.new_device_id || req.body?.device_id, 300).toLowerCase();

      const rawExpectedOld = req.body?.expected_old_device_id;
      const expectedOldDeviceId = (rawExpectedOld != null && String(rawExpectedOld).trim() !== '')
        ? clean(rawExpectedOld, 300).toLowerCase()
        : null;

      if (!key || !newDeviceId || !/^[0-9a-f]{16}$/.test(newDeviceId)) {
        return res.status(400).json({
          success: false,
          code: 'invalid_input',
          message: 'Key dan new_device_id (16 karakter heksadesimal) wajib diisi'
        });
      }

      const { data: rpcRes, error: rpcError } = await supabaseAdmin
        .rpc('nexus_rebind_license', {
          p_key: key,
          p_new_device_id: newDeviceId,
          p_expected_old_device_id: expectedOldDeviceId
        });

      if (rpcError) {
        console.error('[Admin Rebind RPC Error]', rpcError.message);
        if (rpcError.code === '23505') {
          return res.status(400).json({
            success: false,
            code: 'device_already_bound',
            message: 'Target device ID is already bound to another active license'
          });
        }
        return dbFailure(res, 'admin rebind rpc failed', rpcError);
      }

      if (!rpcRes || rpcRes.success !== true) {
        return res.status(400).json({
          success: false,
          code: rpcRes?.code || 'rebind_failed',
          message: rpcRes?.message || 'Rebind gagal'
        });
      }

      return res.json({
        success: true,
        message: rpcRes.message,
        key_masked: rpcRes.key_masked,
        device_suffix: rpcRes.device_suffix
      });
    } catch (error) {
      return dbFailure(res, 'admin rebind endpoint failed', error);
    }
  });
};
