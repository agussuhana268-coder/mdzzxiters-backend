/**
 * MDZZXITERS — Product Delivery Backend v3.1
 * Stack: Express · Supabase Storage · Brevo HTTP API
 */
'use strict';
require('dotenv').config();

const express = require('express');
const rateLimit = require('express-rate-limit');
const cors    = require('cors');
const multer  = require('multer');
const path    = require('path');
const https   = require('https');
const crypto  = require('crypto');
const { promisify } = require('util');
const scryptAsync = promisify(crypto.scrypt);
const { createClient } = require('@supabase/supabase-js');
const admin = require('firebase-admin');


/* ══ CONFIG ══ */
const PORT          = process.env.PORT || 3000;
const SUPABASE_URL  = (process.env.SUPABASE_URL||'').replace('/rest/v1/','').replace(/\/$/,'');
const SUPABASE_KEY  = pickKey();
const BUCKET        = 'products';
const SIGNED_EXPIRY = 900;
const BREVO_API_KEY = process.env.BREVO_API_KEY || '';
const FROM_NAME     = process.env.FROM_NAME  || 'MDZZXITERS Team';
const FROM_EMAIL    = process.env.FROM_EMAIL || '';
const ADMIN_KEY     = process.env.ADMIN_SECRET || 'mdzz_admin_2024';

function pickKey(){
  const svc  = process.env.SUPABASE_SERVICE_KEY || '';
  const anon = process.env.SUPABASE_ANON_KEY    || '';
  if(svc.startsWith('eyJ'))  return svc;
  if(anon.startsWith('eyJ')) return anon;
  return svc||anon;
}

const supabase = createClient(SUPABASE_URL, SUPABASE_KEY, {
  auth: { persistSession: false }
});

const supabaseAdmin = createClient(
  (process.env.SUPABASE_LICENSE_URL || '').replace(/\/rest\/v1\/?$/, '').replace(/\/$/, ''),
  process.env.SUPABASE_LICENSE_SERVICE_KEY || '',
  {
    auth: {
      persistSession: false,
      autoRefreshToken: false
    }
  }
);

console.log('Supabase admin config:', {
  urlSet: !!process.env.SUPABASE_URL,
  serviceKeySet: !!process.env.SUPABASE_SERVICE_KEY,
  serviceKeyLength: (process.env.SUPABASE_SERVICE_KEY || '').length,
  serviceKeyPrefix: (process.env.SUPABASE_SERVICE_KEY || '').slice(0, 12)
});

// Firebase Admin SDK — server-side token verification
if (!admin.apps.length) {
  const serviceAccountJson = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;

  if (!serviceAccountJson) {
    throw new Error('FIREBASE_SERVICE_ACCOUNT_JSON belum diset');
  }

  admin.initializeApp({
    credential: admin.credential.cert(JSON.parse(serviceAccountJson))
  });
}

// Admin metadata and authorization now live in Supabase; Firebase Admin remains for ID-token verification.

/* ══ BREVO HTTP API ══ */
function sendBrevoEmail(to, subject, html, text) {
  return new Promise((resolve, reject) => {
    if (!BREVO_API_KEY) return reject(new Error('BREVO_API_KEY belum diset'));

    const body = JSON.stringify({
      sender:      { name: FROM_NAME, email: FROM_EMAIL },
      to:          [{ email: to }],
      subject:     subject,
      htmlContent: html,
      textContent: text
    });

    const opts = {
      hostname: 'api.brevo.com',
      port:     443,
      path:     '/v3/smtp/email',
      method:   'POST',
      headers: {
        'api-key':        BREVO_API_KEY,
        'Content-Type':   'application/json',
        'Accept':         'application/json',
        'Content-Length': Buffer.byteLength(body)
      }
    };

    const req = https.request(opts, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try {
          const parsed = JSON.parse(data);
          if (res.statusCode >= 200 && res.statusCode < 300) {
            resolve(parsed);
          } else {
            reject(new Error('Brevo API error ' + res.statusCode + ': ' + (parsed.message || data)));
          }
        } catch(e) {
          reject(new Error('Brevo parse error: ' + data.substring(0, 100)));
        }
      });
    });

    req.on('error', e => reject(new Error('Brevo HTTP: ' + e.message)));
    req.setTimeout(20000, () => { req.destroy(); reject(new Error('Brevo timeout 20s')); });
    req.write(body);
    req.end();
  });
}

/* ══ APP ══ */
const app = express();

/* CORS harus berjalan sebelum body parser agar preflight browser selalu mendapat header yang benar. */
const corsOptions = {
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'X-Admin-Key', 'Authorization'],
  optionsSuccessStatus: 204
};
app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

const activationLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: 'Terlalu banyak percobaan aktivasi. Coba lagi nanti.'
  }
});

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 200 * 1024 * 1024 },
  fileFilter: (_, file, cb) => {
    path.extname(file.originalname).toLowerCase() === '.zip'
      ? cb(null, true) : cb(new Error('Hanya .zip'));
  }
});
const avatarUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 3 * 1024 * 1024 },
  fileFilter: (_, file, cb) => {
    ['image/jpeg','image/png','image/webp','image/gif'].includes(file.mimetype)
      ? cb(null, true) : cb(new Error('Foto harus JPG, PNG, WEBP, atau GIF.'));
  }
});

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

function requireAuth(req, res, next) {
  if (req.headers['x-admin-key'] !== ADMIN_KEY)
    return res.status(401).json({ success: false, message: 'Unauthorized' });
  next();
}

function safeEqual(a, b) {
  const aa = Buffer.from(String(a || ''));
  const bb = Buffer.from(String(b || ''));
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}
function signAdminSession(payload) {
  const secret = process.env.ADMIN_SESSION_SECRET || '';
  if (secret.length < 32) throw new Error('ADMIN_SESSION_SECRET harus diset dengan minimal 32 karakter');
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  return body + '.' + crypto.createHmac('sha256', secret).update(body).digest('base64url');
}
function verifyAdminSession(token) {
  const secret = process.env.ADMIN_SESSION_SECRET || '';
  if (secret.length < 32 || !token || token.split('.').length !== 2) return null;
  const parts = token.split('.');
  const expected = crypto.createHmac('sha256', secret).update(parts[0]).digest('base64url');
  if (!safeEqual(parts[1], expected)) return null;
  try {
    const p = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    if (!p.exp || p.exp <= Math.floor(Date.now()/1000) || !p.uid || !p.username || !['owner','admin'].includes(p.role)) return null;
    return p;
  } catch (_) { return null; }
}
function legacySimpleHash(value) {
  let h=0; for(let i=0;i<value.length;i++){h=((h<<5)-h)+value.charCodeAt(i);h|=0;}
  return 'h_'+Math.abs(h).toString(36);
}
async function hashAdminPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const key = await scryptAsync(String(password), salt, 64);
  return 'scrypt$' + salt + '$' + Buffer.from(key).toString('hex');
}

/* ══ GET /download — Halaman redirect iOS-friendly ══ */
app.get('/download', (req, res) => {
  const fileUrl = req.query.url;
  if (!fileUrl || !fileUrl.startsWith('https://')) {
    return res.status(400).send('<h2>Link tidak valid atau sudah kedaluwarsa.</h2>');
  }
  // Encode for keamanan tampilan di HTML
  const safeUrl = fileUrl.replace(/"/g, '%22').replace(/</g, '%3C').replace(/>/g, '%3E');

  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send('<!DOCTYPE html><html lang="id"><head><meta charset="UTF-8"/>'
    + '<meta name="viewport" content="width=device-width,initial-scale=1"/>'
    + '<title>Unduh Produk — MDZZXITERS</title>'
    + '<style>'
    + '*{margin:0;padding:0;box-sizing:border-box}'
    + 'body{background:#060d1a;font-family:Segoe UI,Arial,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}'
    + '.card{background:#0d1628;border:1px solid rgba(56,189,248,.2);border-radius:20px;padding:36px 28px;text-align:center;max-width:400px;width:100%}'
    + '.logo{width:56px;height:56px;border-radius:50%;background:linear-gradient(135deg,#1e3a8a,#0ea5e9);line-height:56px;font-size:22px;font-weight:900;color:#fff;margin:0 auto 18px;font-family:monospace;display:flex;align-items:center;justify-content:center}'
    + 'h1{color:#e2f4ff;font-size:18px;font-weight:700;margin-bottom:8px}'
    + 'p{color:#6288aa;font-size:13px;line-height:1.6;margin-bottom:24px}'
    + '.btn{display:block;background:linear-gradient(135deg,#1e3a8a,#2563eb,#0ea5e9);color:#fff;text-decoration:none;font-weight:700;font-size:15px;padding:16px 32px;border-radius:12px;margin-bottom:14px}'
    + '.url{color:#38bdf8;font-size:11px;word-break:break-all;padding:8px 0;display:block}'
    + '.spin{width:32px;height:32px;border:3px solid rgba(56,189,248,.15);border-top-color:#38bdf8;border-radius:50%;animation:s .8s linear infinite;margin:0 auto 18px}'
    + '@keyframes s{to{transform:rotate(360deg)}}'
    + '</style></head><body>'
    + '<div class="card">'
    + '<div class="logo">M</div>'
    + '<div class="spin"></div>'
    + '<h1>Mempersiapkan Unduhan...</h1>'
    + '<p>File sedang disiapkan. Klik tombol di bawah jika unduhan tidak dimulai otomatis.</p>'
    + '<a href="' + safeUrl + '" class="btn">&#11015; UNDUH SEKARANG</a>'
    + '<a href="' + safeUrl + '" class="url">Tap link ini jika tombol tidak berfungsi</a>'
    + '<p style="margin-top:16px;font-size:11px;color:#334155;">MDZZXITERS &middot; Link kedaluwarsa dalam 15 menit</p>'
    + '</div>'
    + '<script>setTimeout(function(){window.location.href="' + safeUrl + '";},2000);</script>'
    + '</body></html>');
});

/* ══ GET /api/health ══ */
app.get('/api/health', async (_, res) => {
  res.header('Access-Control-Allow-Origin', '*');
  const keyType = (process.env.SUPABASE_SERVICE_KEY||'').startsWith('eyJ') ? 'service_role' : 'anon';

  let bucketOk = false, bucketErr = null;
  try {
    const { data, error } = await Promise.race([
      supabase.storage.from(BUCKET).list('', { limit: 1 }),
      new Promise((_,rej) => setTimeout(() => rej(new Error('timeout')), 8000))
    ]);
    bucketOk = !error;
    if (error) bucketErr = error.message;
  } catch(e) { bucketErr = e.message; }

  res.json({
    success:   true,
    status:    'online',
    supabase:  !!(SUPABASE_URL && SUPABASE_KEY),
    keyType:   keyType,
    bucket:    bucketOk ? 'accessible' : ('ERROR: ' + bucketErr),
    brevo_api: !!BREVO_API_KEY,
    from:      FROM_EMAIL,
    timestamp: new Date().toISOString()
  });
});

/* ══ GET /api/products ══ */
app.get('/api/products', requireAuth, async (_, res) => {
  try {
    const { data, error } = await supabase.storage
      .from(BUCKET).list('', { limit: 200, sortBy: { column: 'name', order: 'asc' } });
    if (error) throw error;
    const files = (data||[]).filter(f => f.name && f.name.endsWith('.zip'))
      .map(f => ({ name: f.name, size: f.metadata?.size||0, updatedAt: f.updated_at||f.created_at||null }));
    res.json({ success: true, files });
  } catch(e) {
    console.error('[products]', e.message);
    res.status(500).json({ success: false, message: e.message });
  }
});

/* ══ POST /api/upload-product ══ */
app.post('/api/upload-product', requireAuth, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ success: false, message: 'Tidak ada file' });
    const raw  = (req.body.fileName || req.file.originalname).trim();
    const safe = raw.toLowerCase().replace(/\s+/g,'-').replace(/[^a-z0-9._-]/g,'');
    const dest = safe.endsWith('.zip') ? safe : safe + '.zip';
    const { error } = await supabase.storage.from(BUCKET)
      .upload(dest, req.file.buffer, { contentType: 'application/zip', upsert: true });
    if (error) throw error;
    console.log('[upload] OK →', dest);
    res.json({ success: true, message: '"' + dest + '" berhasil diunggah', path: dest, size: req.file.size });
  } catch(e) {
    console.error('[upload]', e.message);
    res.status(500).json({ success: false, message: e.message });
  }
});

/* ══ DELETE /api/products/:fn ══ */
app.delete('/api/products/:fn', requireAuth, async (req, res) => {
  try {
    const fn = decodeURIComponent(req.params.fn);
    const { error } = await supabase.storage.from(BUCKET).remove([fn]);
    if (error) throw error;
    res.json({ success: true, message: '"' + fn + '" berhasil dihapus' });
  } catch(e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

/* ══ POST /api/send-product ══ */
app.post('/api/send-product', requireAuth, async (req, res) => {
  const { buyerEmail, productName, licenseKey, fileName } = req.body;
  if (!buyerEmail || !productName || !licenseKey || !fileName)
    return res.status(400).json({ success: false, message: 'Semua field wajib diisi' });

  try {
    /* Step 1: Signed URL */
    console.log('[send] Step 1 — Signed URL:', fileName);
    const { data: sd, error: se } = await Promise.race([
      supabase.storage.from(BUCKET).createSignedUrl(fileName, SIGNED_EXPIRY),
      new Promise((_,rej) => setTimeout(() => rej(new Error('Supabase timeout 10s')), 10000))
    ]);
    if (se) throw new Error('Supabase: ' + se.message);
    if (!sd || !sd.signedUrl) throw new Error('Signed URL kosong — cek nama file di bucket');

    const rawDownloadUrl = sd.signedUrl;
    const expireDate     = new Date(Date.now() + SIGNED_EXPIRY * 1000);
    const expireStr      = expireDate.toLocaleString('id-ID', {
      day:'2-digit', month:'long', year:'numeric',
      hour:'2-digit', minute:'2-digit', timeZone:'Asia/Jakarta'
    }) + ' WIB';

    /* Buat redirect URL untuk iOS — gunakan server sendiri sebagai perantara */
    const proto       = req.headers['x-forwarded-proto'] || 'https';
    const host        = req.headers['x-forwarded-host']  || req.headers.host || '';
    const redirectUrl = host
      ? proto + '://' + host + '/download?url=' + encodeURIComponent(rawDownloadUrl)
      : rawDownloadUrl;

    console.log('[send] redirectUrl:', redirectUrl.substring(0, 80) + '...');

    /* Step 2: Build email HTML — substitusi dilakukan di sini, bukan di template string */
    const emailHtml = buildEmailHtml(buyerEmail, productName, licenseKey, redirectUrl, expireStr);
    const emailText = 'Produk: ' + productName + '\nLicense: ' + licenseKey
      + '\nDownload: ' + redirectUrl + '\nExpired: ' + expireStr;

    /* Step 3: Kirim via Brevo HTTP API */
    console.log('[send] Step 2 — Sending email to:', buyerEmail);
    const result = await sendBrevoEmail(
      buyerEmail,
      '[MDZZXITERS] Produk Anda: ' + productName,
      emailHtml,
      emailText
    );

    console.log('[send] OK →', buyerEmail, '| id:', result.messageId || 'sent');
    res.json({ success: true, message: 'Email berhasil dikirim ke ' + buyerEmail, expiresAt: expireStr });

  } catch(e) {
    console.error('[send] ERROR:', e.message);
    res.status(500).json({ success: false, message: e.message });
  }
});

/* ══ EMAIL HTML — string concatenation, NO template literals ══ */
/* Ini mencegah bug ${var} tidak ter-substitusi */
function buildEmailHtml(buyerEmail, productName, licenseKey, redirectUrl, expireStr) {
  return '<!DOCTYPE html><html lang="id"><head><meta charset="UTF-8"/>'
    + '<meta name="viewport" content="width=device-width,initial-scale=1"/>'
    + '</head><body style="margin:0;padding:0;background:#0a0f1e;font-family:Segoe UI,Arial,sans-serif;">'
    + '<table width="100%" cellpadding="0" cellspacing="0" style="background:#0a0f1e;padding:36px 16px;">'
    + '<tr><td align="center">'
    + '<table width="100%" style="max-width:540px;background:#0d1628;border-radius:20px;overflow:hidden;border:1px solid rgba(56,189,248,.18);">'

    /* Header */
    + '<tr><td style="background:linear-gradient(135deg,#1e3a8a,#1d4ed8,#0ea5e9);padding:36px 32px 28px;text-align:center;">'
    + '<div style="width:58px;height:58px;border-radius:50%;background:rgba(255,255,255,.15);line-height:58px;font-size:24px;font-weight:900;color:#fff;font-family:monospace;margin:0 auto 14px;display:inline-block;">M</div>'
    + '<h1 style="margin:0;color:#fff;font-size:21px;font-weight:700;letter-spacing:1.5px;">MDZZXITERS</h1>'
    + '<p style="margin:6px 0 0;color:rgba(255,255,255,.65);font-size:11px;letter-spacing:2.5px;">PRODUK SIAP DIUNDUH</p>'
    + '</td></tr>'

    /* Body */
    + '<tr><td style="padding:30px 30px 22px;">'
    + '<p style="margin:0 0 22px;color:#94a3b8;font-size:13px;line-height:1.6;">Halo! Terima kasih telah membeli produk kami. Berikut detail lisensi dan tautan unduhan Anda.</p>'

    /* Produk */
    + '<table width="100%" style="background:rgba(56,189,248,.06);border:1px solid rgba(56,189,248,.16);border-radius:12px;margin-bottom:12px;">'
    + '<tr><td style="padding:18px 20px;">'
    + '<div style="font-size:10px;color:#475569;letter-spacing:2.5px;font-family:monospace;margin-bottom:5px;">NAMA PRODUK</div>'
    + '<div style="font-size:19px;font-weight:700;color:#e2f4ff;">' + productName + '</div>'
    + '</td></tr></table>'

    /* License Key */
    + '<table width="100%" style="background:rgba(16,185,129,.06);border:1px solid rgba(16,185,129,.2);border-radius:12px;margin-bottom:20px;">'
    + '<tr><td style="padding:18px 20px;">'
    + '<div style="font-size:10px;color:#475569;letter-spacing:2.5px;font-family:monospace;margin-bottom:7px;">LICENSE KEY</div>'
    + '<div style="font-size:17px;font-weight:700;color:#34d399;font-family:monospace;letter-spacing:2px;word-break:break-all;">' + licenseKey + '</div>'
    + '</td></tr></table>'

    /* Tombol Download */
    + '<table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:12px;">'
    + '<tr><td align="center">'
    + '<a href="' + redirectUrl + '" target="_blank" rel="noopener noreferrer"'
    + ' style="display:inline-block;background:linear-gradient(135deg,#1e3a8a,#2563eb,#0ea5e9);'
    + 'color:#ffffff;text-decoration:none;font-weight:700;font-size:16px;'
    + 'padding:18px 48px;border-radius:12px;letter-spacing:.5px;">'
    + '&#11015; UNDUH PRODUK SEKARANG'
    + '</a>'
    + '</td></tr></table>'

    /* Plain URL fallback untuk iOS */
    + '<table width="100%" style="margin-bottom:20px;">'
    + '<tr><td style="text-align:center;padding:10px 16px;background:rgba(0,0,0,.2);border-radius:10px;">'
    + '<p style="margin:0 0 5px;color:#475569;font-size:10px;font-family:monospace;letter-spacing:1.5px;">BUKA LINK INI DI BROWSER JIKA TOMBOL TIDAK BERFUNGSI:</p>'
    + '<a href="' + redirectUrl + '" target="_blank" style="color:#38bdf8;font-size:11px;word-break:break-all;">' + redirectUrl + '</a>'
    + '</td></tr></table>'

    /* Expiry */
    + '<table width="100%" style="background:rgba(245,158,11,.07);border:1px solid rgba(245,158,11,.18);border-radius:11px;margin-bottom:24px;">'
    + '<tr><td style="padding:13px 18px;">'
    + '<p style="margin:0;color:#fbbf24;font-size:12px;font-family:monospace;line-height:1.7;">'
    + '&#9201; Link kedaluwarsa dalam <strong>15 menit</strong><br/>'
    + 'Batas: <strong>' + expireStr + '</strong>'
    + '</p></td></tr></table>'

    + '<p style="margin:0;color:#334155;font-size:12px;line-height:1.7;">Simpan license key di tempat aman. Jika link kedaluwarsa, hubungi admin untuk link baru.</p>'
    + '</td></tr>'

    /* Footer */
    + '<tr><td style="background:rgba(0,0,0,.28);padding:18px 30px;text-align:center;border-top:1px solid rgba(56,189,248,.07);">'
    + '<p style="margin:0;color:#1e3a5a;font-size:10px;font-family:monospace;letter-spacing:1px;">'
    + 'MDZZXITERS CORPORATION &middot; AUTOMATED DELIVERY<br/>Pesan dikirim otomatis &mdash; jangan dibalas.'
    + '</p></td></tr>'

    + '</table></td></tr></table></body></html>';
}

/* ── Error handler ── */
app.use((err, _, res, __) => {
  if (err.code === 'LIMIT_FILE_SIZE')
    return res.status(413).json({ success: false, message: 'File terlalu besar (max 200MB)' });
  res.status(500).json({ success: false, message: err.message });
});

app.post('/api/admin/session', requireFirebaseAdmin, async (req, res) => {
  try {
    const username = String(req.verifiedAdmin?.username || '')
      .trim()
      .toLowerCase();

    if (!username) {
      return res.status(403).json({
        success: false,
        message: 'Profil admin tidak ditemukan',
        code: 'ADMIN_PROFILE_REQUIRED'
      });
    }

    const { data: activeAdmin, error } = await supabaseAdmin
      .from('admins')
      .select('id,username,name,role,created_at,avatar_url')
      .eq('username', username)
      .maybeSingle();

    if (error) {
      console.error('Admin session profile lookup failed:', error);
      return res.status(503).json({
        success: false,
        message: 'Gagal memverifikasi profil admin'
      });
    }

    if (
      !activeAdmin ||
      !['owner', 'admin'].includes(activeAdmin.role) ||
      activeAdmin.role !== req.verifiedAdmin.role
    ) {
      return res.status(403).json({
        success: false,
        message: 'Akun admin tidak aktif atau role tidak cocok',
        code: 'ADMIN_ACCESS_REVOKED'
      });
    }

    const now = Math.floor(Date.now() / 1000);
    const token = signAdminSession({
      uid: String(activeAdmin.id),
      username: activeAdmin.username,
      name: activeAdmin.name || activeAdmin.username,
      role: activeAdmin.role,
      iat: now,
      exp: now + 8 * 60 * 60
    });

    return res.set('Cache-Control', 'no-store').json({
      success: true,
      token,
      expires_in: 28800,
      admin: {
        id: activeAdmin.id,
        username: activeAdmin.username,
        name: activeAdmin.name || activeAdmin.username,
        role: activeAdmin.role,
        created_at: activeAdmin.created_at || null,
        avatar_url: activeAdmin.avatar_url || null
      }
    });
  } catch (err) {
    console.error('Admin session exchange failed:', err);
    return res.status(500).json({
      success: false,
      message: 'Gagal membuat sesi admin'
    });
  }
});

app.get('/api/admin/verify', requireFirebaseAdmin, (req, res) => {
  res.set('Cache-Control', 'no-store').json({
    success: true,
    message: 'Firebase admin berhasil diverifikasi',
    admin: {
      uid: req.verifiedAdmin.uid,
      username: req.verifiedAdmin.username,
      name: req.verifiedAdmin.name || req.verifiedAdmin.username,
      role: req.verifiedAdmin.role
    }
  });
});

/* Refresh status lisensi untuk panel admin. Supabase service key hanya di backend. */

/* Riwayat perubahan IP hanya dibaca melalui backend terautentikasi. */
app.get('/api/ip-history', requireFirebaseAdmin, async (_req, res) => {
  try {
    const { data, error } = await supabaseAdmin
      .from('ip_history')
      .select('id,license_key,ip_address,device_id,created_at')
      .order('created_at', { ascending: false })
      .limit(300);
    if (error) {
      console.error('GET /api/ip-history Supabase error:', error.message);
      return res.status(502).json({ success: false, message: 'Gagal memuat riwayat IP dari Supabase.' });
    }
    return res.set('Cache-Control', 'no-store').json({ success: true, rows: data || [] });
  } catch (err) {
    console.error('GET /api/ip-history gagal:', err.message);
    return res.status(500).json({ success: false, message: 'Gagal memuat riwayat IP.' });
  }
});

app.get('/api/licenses/status', requireFirebaseAdmin, async (_req, res) => {
  try {
    const { data, error } = await supabaseAdmin
      .from('licenses')
      .select('key,project,active,used,device_id,status,generated_by,created_at,expires_at,used_at,last_seen,current_ip,first_ip,last_ip,nexus_id')
      .order('key', { ascending: true })
      .limit(5000);

    if (error) {
      console.error('GET /api/licenses/status Supabase error:', {
        message: error.message, code: error.code, details: error.details, hint: error.hint
      });
      return res.status(502).json({
        success: false,
        message: 'Supabase menolak permintaan status. Periksa SUPABASE_LICENSE_URL dan SUPABASE_LICENSE_SERVICE_KEY di backend.'
      });
    }

    return res.set('Cache-Control', 'no-store').json({
      success: true,
      count: (data || []).length,
      rows: data || []
    });
  } catch (err) {
    console.error('GET /api/licenses/status gagal:', err.message);
    return res.status(500).json({
      success: false,
      message: 'Gagal memuat status lisensi dari backend.'
    });
  }
});

/* Set password khusus dashboard untuk satu-satunya akun owner.
   Endpoint sementara migrasi: wajib memakai sesi Firebase owner yang lolos ADMIN_UID_ALLOWLIST.
   Password hanya disimpan sebagai hash scrypt di Supabase dan tidak pernah dikembalikan. */
app.post('/api/admin/owner-password', requireFirebaseAdmin, async (req, res) => {
  try {
    if (req.verifiedAdmin?.role !== 'owner') {
      return res.status(403).set('Cache-Control', 'no-store').json({
        success: false,
        message: 'Hanya owner yang dapat menyiapkan password dashboard.'
      });
    }

    const password = typeof req.body?.password === 'string' ? req.body.password : '';
    if (password.length < 12 || password.length > 256) {
      return res.status(400).set('Cache-Control', 'no-store').json({
        success: false,
        message: 'Password dashboard harus 12–256 karakter.'
      });
    }

    const { data: owners, error: lookupError } = await supabaseAdmin
      .from('admins')
      .select('id,username,role')
      .eq('role', 'owner')
      .limit(2);

    if (lookupError) {
      console.error('Owner password lookup failed:', lookupError.message);
      return res.status(502).set('Cache-Control', 'no-store').json({
        success: false,
        message: 'Gagal memeriksa akun owner di Supabase.'
      });
    }
    if (!owners || owners.length !== 1) {
      return res.status(409).set('Cache-Control', 'no-store').json({
        success: false,
        message: 'Harus ada tepat satu akun owner di tabel admins sebelum password dapat disiapkan.'
      });
    }

    const passwordHash = await hashAdminPassword(password);
    const { error: updateError } = await supabaseAdmin
      .from('admins')
      .update({ password: passwordHash })
      .eq('id', owners[0].id)
      .eq('role', 'owner');

    if (updateError) {
      console.error('Owner password update failed:', updateError.message);
      return res.status(502).set('Cache-Control', 'no-store').json({
        success: false,
        message: 'Gagal menyimpan password owner di Supabase.'
      });
    }

    return res.set('Cache-Control', 'no-store').json({
      success: true,
      message: 'Password dashboard owner berhasil disiapkan. Login berikutnya dapat menggunakan username dan password Supabase.'
    });
  } catch (err) {
    console.error('Owner password setup failed:', err.message);
    return res.status(500).set('Cache-Control', 'no-store').json({
      success: false,
      message: 'Gagal menyiapkan password dashboard owner.'
    });
  }
});

/* Login username/password admin melalui backend. Password tidak pernah dikirim kembali. */
const adminLoginLimiter = rateLimit({windowMs:15*60*1000,limit:10,standardHeaders:true,legacyHeaders:false,message:{success:false,message:'Terlalu banyak percobaan login. Coba lagi dalam 15 menit.'}});
app.post('/api/admin/login', adminLoginLimiter, async (req,res)=>{
  try{
    const username=String(req.body?.username||'').trim().toLowerCase();
    const password=typeof req.body?.password==='string'?req.body.password:'';
    if(!/^[a-z0-9_.-]{3,40}$/.test(username)||!password||password.length>256)
      return res.status(400).json({success:false,message:'Username atau password tidak valid.'});
    const {data,error}=await supabaseAdmin.from('admins').select('id,username,password,name,role,created_at,avatar_url').eq('username',username).maybeSingle();
    if(error){console.error('Admin login lookup:',error.message);return res.status(502).json({success:false,message:'Layanan login admin sementara tidak tersedia.'});}
    if(!data||!['owner','admin'].includes(data.role)||!(await verifyAdminPassword(password,data.password)))
      return res.status(401).json({success:false,message:'Username atau password salah.'});
    if(String(process.env.ADMIN_SESSION_SECRET||'').length<32)
      return res.status(503).json({success:false,message:'Autentikasi admin belum dikonfigurasi di backend.'});
    if(!String(data.password).startsWith('scrypt$')){
      const upgraded=await hashAdminPassword(password);
      const {error:upgradeError}=await supabaseAdmin.from('admins').update({password:upgraded}).eq('id',data.id);
      if(upgradeError){console.error('Password hash upgrade failed:',upgradeError.message);return res.status(503).json({success:false,message:'Login aman belum dapat diselesaikan. Coba lagi.'});}
    }
    const now=Math.floor(Date.now()/1000);
    const token=signAdminSession({uid:String(data.id),username:data.username,name:data.name||data.username,role:data.role,iat:now,exp:now+8*60*60});
    return res.set('Cache-Control','no-store').json({success:true,token,expires_in:28800,admin:{id:data.id,username:data.username,name:data.name||data.username,role:data.role,created_at:data.created_at||null,avatar_url:data.avatar_url||null}});
  }catch(err){console.error('Admin login failed:',err.message);return res.status(500).json({success:false,message:'Login admin gagal.'});}
});

/* Upload avatar lewat backend agar Supabase service key tidak pernah berada di browser. */
app.post('/api/admins/me/avatar', requireFirebaseAdmin, avatarUpload.single('file'), async (req,res)=>{
  try{
    if(!req.file)return res.status(400).json({success:false,message:'Pilih file foto terlebih dahulu.'});
    const ext=({'image/jpeg':'jpg','image/png':'png','image/webp':'webp','image/gif':'gif'})[req.file.mimetype];
    if(!ext)return res.status(400).json({success:false,message:'Format foto tidak didukung.'});
    const bucket=String(process.env.AVATAR_BUCKET||'avatar').trim();
    const objectPath='avatars/'+String(req.verifiedAdmin.uid).replace(/[^a-zA-Z0-9_-]/g,'_')+'.'+ext;
    const {error:uploadError}=await supabaseAdmin.storage.from(bucket).upload(objectPath,req.file.buffer,{contentType:req.file.mimetype,upsert:true,cacheControl:'3600'});
    if(uploadError){
      console.error('Avatar upload Supabase error:',uploadError.message);
      return res.status(502).json({success:false,message:'Gagal mengunggah foto. Periksa bucket Storage avatar di Supabase.'});
    }
    const {data:urlData}=supabaseAdmin.storage.from(bucket).getPublicUrl(objectPath);
    const avatar_url=urlData?.publicUrl;
    if(!avatar_url)return res.status(502).json({success:false,message:'URL foto tidak berhasil dibuat.'});
    const {data:existing,error:findError}=await supabaseAdmin.from('admins').select('id').eq('username',req.verifiedAdmin.username).maybeSingle();
    if(findError){console.error('Avatar profile lookup:',findError.message);return res.status(502).json({success:false,message:'Foto terunggah tetapi profil gagal diperbarui.'});}
    if(existing){
      const {error:updateError}=await supabaseAdmin.from('admins').update({avatar_url}).eq('id',existing.id);
      if(updateError){console.error('Avatar profile update:',updateError.message);return res.status(502).json({success:false,message:'Foto terunggah tetapi profil gagal diperbarui.'});}
    }else if(req.verifiedAdmin.role==='owner'){
      const {error:createError}=await supabaseAdmin.from('admins').insert({username:req.verifiedAdmin.username,name:req.verifiedAdmin.name||req.verifiedAdmin.username,role:'owner',avatar_url});
      if(createError){console.error('Avatar owner profile create:',createError.message);return res.status(502).json({success:false,message:'Foto terunggah, tetapi profil owner belum dapat dibuat. Periksa apakah kolom password mengizinkan NULL.'});}
    }else{
      return res.status(409).json({success:false,code:'ADMIN_PROFILE_NOT_FOUND',message:'Profil admin belum dimigrasikan ke Supabase.'});
    }
    return res.json({success:true,avatar_url});
  }catch(err){console.error('POST /api/admins/me/avatar failed:',err.message);return res.status(500).json({success:false,message:'Gagal memproses foto profil.'});}
});

/* Profil admin saat ini. Owner UID allowlist boleh memiliki profil virtual sampai migrasi data selesai. */
app.get('/api/admins/me', requireFirebaseAdmin, async (req, res) => {
  try {
    const { data, error } = await supabaseAdmin.from('admins')
      .select('id,username,name,role,created_at,avatar_url')
      .eq('username', req.verifiedAdmin.username).maybeSingle();
    if (error) {
      console.error('GET /api/admins/me Supabase error:', error.message);
      return res.status(502).json({ success: false, message: 'Gagal membaca profil admin dari Supabase.' });
    }
    const isOwner = req.verifiedAdmin.role === 'owner';
    if (!data && !isOwner) return res.status(404).json({ success: false, code: 'ADMIN_PROFILE_NOT_FOUND', message: 'Profil belum ada di Supabase. Migrasikan data admin terlebih dahulu.' });
    return res.set('Cache-Control', 'no-store').json({
      success: true,
      profile: data || {
        id: req.verifiedAdmin.uid,
        username: req.verifiedAdmin.username,
        name: req.verifiedAdmin.name || req.verifiedAdmin.username,
        role: req.verifiedAdmin.role,
        created_at: null,
        avatar_url: null,
        virtual: true
      }
    });
  } catch (err) {
    console.error('GET /api/admins/me gagal:', err.message);
    return res.status(500).json({ success: false, message: 'Gagal memuat profil admin.' });
  }
});

app.patch('/api/admins/me', requireFirebaseAdmin, async (req, res) => {
  try {
    const name = req.body?.name == null ? undefined : String(req.body.name).trim().slice(0, 100);
    const avatar_url = req.body?.avatar_url == null ? undefined : String(req.body.avatar_url).trim().slice(0, 1000);
    if (name !== undefined && !name) return res.status(400).json({ success: false, message: 'Nama tidak boleh kosong.' });
    if (avatar_url !== undefined && avatar_url && !/^https:\/\//i.test(avatar_url)) return res.status(400).json({ success: false, message: 'URL foto harus menggunakan HTTPS.' });
    if (name === undefined && avatar_url === undefined) return res.status(400).json({ success: false, message: 'Tidak ada perubahan profil.' });
    const { data: existing, error: findError } = await supabaseAdmin.from('admins')
      .select('id,username,name,role,created_at,avatar_url')
      .eq('username', req.verifiedAdmin.username).maybeSingle();
    if (findError) {
      console.error('PATCH /api/admins/me lookup error:', findError.message);
      return res.status(502).json({ success: false, message: 'Gagal memeriksa profil admin di Supabase.' });
    }
    if (!existing) {
      if (req.verifiedAdmin.role !== 'owner') {
        return res.status(409).json({ success: false, code: 'ADMIN_PROFILE_NOT_FOUND', message: 'Profil admin belum dimigrasikan ke Supabase.' });
      }
      // Owner yang sudah diverifikasi melalui Firebase UID allowlist boleh membuat metadata profilnya sendiri.
      const ownerRow = {
        username: req.verifiedAdmin.username,
        name: name !== undefined ? name : (req.verifiedAdmin.name || req.verifiedAdmin.username),
        role: 'owner',
        avatar_url: avatar_url !== undefined ? (avatar_url || null) : null
      };
      const { data: created, error: createError } = await supabaseAdmin.from('admins')
        .insert(ownerRow).select('id,username,name,role,created_at,avatar_url').single();
      if (createError) {
        console.error('PATCH /api/admins/me owner profile create error:', createError.message);
        return res.status(502).json({ success: false, message: 'Profil owner belum ada dan belum bisa dibuat. Pastikan kolom password di tabel admins boleh NULL, atau siapkan migrasi metadata admin terlebih dahulu.' });
      }
      return res.set('Cache-Control', 'no-store').json({ success: true, profile: created });
    }
    const patch = {};
    if (name !== undefined) patch.name = name;
    if (avatar_url !== undefined) patch.avatar_url = avatar_url || null;
    const { data, error } = await supabaseAdmin.from('admins').update(patch).eq('id', existing.id)
      .select('id,username,name,role,created_at,avatar_url').single();
    if (error) {
      console.error('PATCH /api/admins/me update error:', error.message);
      return res.status(502).json({ success: false, message: 'Gagal menyimpan profil admin ke Supabase.' });
    }
    return res.set('Cache-Control', 'no-store').json({ success: true, profile: data });
  } catch (err) {
    console.error('PATCH /api/admins/me gagal:', err.message);
    return res.status(500).json({ success: false, message: 'Gagal menyimpan profil admin.' });
  }
});

/* Admin CRUD: hanya owner boleh mengelola akun. Password tidak dikembalikan ke browser. */
app.get('/api/admins', requireFirebaseAdmin, async (_req,res)=>{
  try{
    const {data,error}=await supabaseAdmin.from('admins').select('id,username,name,role,created_at,avatar_url').order('created_at',{ascending:true}).limit(500);
    if(error){console.error('GET /api/admins:',error.message);return res.status(502).json({success:false,message:'Gagal membaca daftar admin dari Supabase.'});}
    return res.set('Cache-Control','no-store').json({success:true,count:(data||[]).length,rows:data||[]});
  }catch(err){console.error('GET /api/admins gagal:',err.message);return res.status(500).json({success:false,message:'Gagal memuat daftar admin.'});}
});
app.post('/api/admins', requireFirebaseAdmin, async (req,res)=>{
  try{
    if(req.verifiedAdmin.role!=='owner')return res.status(403).json({success:false,message:'Hanya owner yang dapat menambah admin.'});
    const username=String(req.body?.username||'').trim().toLowerCase();
    const name=String(req.body?.name||'').trim().slice(0,100);
    const password=typeof req.body?.password==='string'?req.body.password:'';
    if(!/^[a-z0-9_.-]{3,40}$/.test(username))return res.status(400).json({success:false,message:'Username harus 3–40 karakter: huruf, angka, titik, garis bawah, atau tanda hubung.'});
    if(!name)return res.status(400).json({success:false,message:'Nama admin wajib diisi.'});
    if(password.length<8||password.length>256)return res.status(400).json({success:false,message:'Password admin baru minimal 8 karakter.'});
    const passwordHash=await hashAdminPassword(password);
    const {data,error}=await supabaseAdmin.from('admins').insert({username,name,role:'admin',password:passwordHash}).select('id,username,name,role,created_at,avatar_url').single();
    if(error){if(error.code==='23505')return res.status(409).json({success:false,message:'Username sudah digunakan.'});console.error('POST /api/admins:',error.message);return res.status(502).json({success:false,message:'Gagal membuat admin di Supabase. Periksa tabel admins.'});}
    return res.status(201).set('Cache-Control','no-store').json({success:true,admin:data});
  }catch(err){console.error('POST /api/admins gagal:',err.message);return res.status(500).json({success:false,message:'Gagal menambah admin.'});}
});
app.delete('/api/admins/:id', requireFirebaseAdmin, async (req,res)=>{
  try{
    if(req.verifiedAdmin.role!=='owner')return res.status(403).json({success:false,message:'Hanya owner yang dapat menghapus admin.'});
    const {data:target,error:lookupError}=await supabaseAdmin.from('admins').select('id,username,role').eq('id',req.params.id).maybeSingle();
    if(lookupError){console.error('DELETE /api/admins lookup:',lookupError.message);return res.status(502).json({success:false,message:'Gagal memeriksa admin.'});}
    if(!target)return res.status(404).json({success:false,message:'Admin tidak ditemukan.'});
    if(target.role==='owner'||target.username===req.verifiedAdmin.username)return res.status(403).json({success:false,message:'Akun owner tidak boleh dihapus.'});
    const {error}=await supabaseAdmin.from('admins').delete().eq('id',req.params.id);
    if(error){console.error('DELETE /api/admins:',error.message);return res.status(502).json({success:false,message:'Gagal menghapus admin dari Supabase.'});}
    return res.set('Cache-Control','no-store').json({success:true});
  }catch(err){console.error('DELETE /api/admins gagal:',err.message);return res.status(500).json({success:false,message:'Gagal menghapus admin.'});}
});

/* Activity log panel disimpan di Supabase, bukan Firestore. */
app.get('/api/activity', requireFirebaseAdmin, async (_req, res) => {
  try {
    const { data, error } = await supabaseAdmin.from('activity_log').select('id,type,text,admin,created_at').order('created_at', { ascending: false }).limit(200);
    if (error) {
      console.error('GET /api/activity Supabase error:', error.message);
      return res.status(502).json({ success: false, message: 'Gagal membaca activity log dari Supabase. Pastikan kolom tabel activity_log sesuai.' });
    }
    return res.set('Cache-Control', 'no-store').json({ success: true, count: (data || []).length, rows: data || [] });
  } catch (err) {
    console.error('GET /api/activity gagal:', err.message);
    return res.status(500).json({ success: false, message: 'Gagal memuat activity log.' });
  }
});

app.post('/api/activity', requireFirebaseAdmin, async (req, res) => {
  try {
    const type = String(req.body?.type || '').trim().slice(0, 40);
    const message = String(req.body?.text || '').trim().slice(0, 5000);
    const actor = String(req.verifiedAdmin.name || req.verifiedAdmin.username || req.verifiedAdmin.uid).trim().slice(0, 120);
    if (!type || !message) return res.status(400).json({ success: false, message: 'Tipe dan isi activity wajib diisi.' });
    const { data, error } = await supabaseAdmin.from('activity_log').insert({ type, text: message, admin: actor }).select('id,type,text,admin,created_at').single();
    if (error) {
      console.error('POST /api/activity Supabase error:', error.message);
      return res.status(502).json({ success: false, message: 'Gagal menyimpan activity log ke Supabase. Pastikan kolom tabel activity_log sesuai.' });
    }
    return res.status(201).set('Cache-Control', 'no-store').json({ success: true, activity: data });
  } catch (err) {
    console.error('POST /api/activity gagal:', err.message);
    return res.status(500).json({ success: false, message: 'Gagal menyimpan activity log.' });
  }
});

/* Data proyek panel admin tersimpan di Supabase. */
app.get('/api/projects', requireFirebaseAdmin, async (_req, res) => {
  try {
    let { data, error } = await supabaseAdmin.from('projects').select('id,name,created_at').order('name', { ascending: true }).limit(500);
    if (error) {
      console.error('GET /api/projects Supabase error:', error.message);
      return res.status(502).json({ success: false, message: 'Gagal membaca proyek dari Supabase.' });
    }
    /* Seed daftar proyek standar hanya jika tabel benar-benar kosong. */
    if (!data || data.length === 0) {
      const defaults = ['INSANITY MAX','CYBER PRO','BLAZE','ATOMIC PRO','ZX PRIVATE','ZX CORE','ZX EXCLUSIVE','ZX APEX','VORTEX'];
      const seeded = await supabaseAdmin.from('projects').insert(defaults.map(name => ({ name }))).select('id,name,created_at');
      if (seeded.error) {
        console.error('Seed projects Supabase error:', seeded.error.message);
        return res.status(502).json({ success: false, message: 'Tabel proyek kosong dan gagal diisi. Periksa tabel projects di Supabase.' });
      }
      data = seeded.data || [];
    }
    return res.set('Cache-Control', 'no-store').json({ success: true, rows: data || [] });
  } catch (err) {
    console.error('GET /api/projects gagal:', err.message);
    return res.status(500).json({ success: false, message: 'Gagal memuat proyek.' });
  }
});

app.post('/api/projects', requireFirebaseAdmin, async (req, res) => {
  try {
    if (req.verifiedAdmin.role !== 'owner') return res.status(403).json({ success: false, message: 'Hanya owner yang dapat mengelola proyek.' });
    const name = String((req.body && req.body.name) || '').trim().toUpperCase();
    if (!name || name.length > 80 || name === 'PRIVATE EXTREME') return res.status(400).json({ success: false, message: 'Nama proyek tidak valid.' });
    const { data, error } = await supabaseAdmin.from('projects').insert({ name }).select('id,name,created_at').single();
    if (error) {
      if (error.code === '23505') return res.status(409).json({ success: false, message: 'Proyek sudah ada.' });
      console.error('POST /api/projects Supabase error:', error.message);
      return res.status(502).json({ success: false, message: 'Gagal menyimpan proyek ke Supabase.' });
    }
    return res.status(201).json({ success: true, project: data });
  } catch (err) {
    console.error('POST /api/projects gagal:', err.message);
    return res.status(500).json({ success: false, message: 'Gagal membuat proyek.' });
  }
});

app.delete('/api/projects/:id', requireFirebaseAdmin, async (req, res) => {
  try {
    if (req.verifiedAdmin.role !== 'owner') return res.status(403).json({ success: false, message: 'Hanya owner yang dapat mengelola proyek.' });
    const { data, error } = await supabaseAdmin.from('projects').delete().eq('id', req.params.id).select('id');
    if (error) {
      console.error('DELETE /api/projects Supabase error:', error.message);
      return res.status(502).json({ success: false, message: 'Gagal menghapus proyek.' });
    }
    if (!data || !data.length) return res.status(404).json({ success: false, message: 'Proyek tidak ditemukan.' });
    return res.json({ success: true });
  } catch (err) {
    console.error('DELETE /api/projects gagal:', err.message);
    return res.status(500).json({ success: false, message: 'Gagal menghapus proyek.' });
  }
});

/* Sesi dashboard dibaca dari Supabase, bukan Firestore. */
app.get('/api/sessions/status', requireFirebaseAdmin, async (_req, res) => {
  try {
    const { data, error } = await supabaseAdmin
      .from('sessions')
      .select('id,key,platform,online,last_seen,ip_address,last_seen_ip_at')
      .order('last_seen', { ascending: false })
      .limit(5000);
    if (error) {
      console.error('GET /api/sessions/status Supabase error:', error.message);
      return res.status(502).json({ success: false, message: 'Gagal membaca sesi dari Supabase.' });
    }
    return res.set('Cache-Control', 'no-store').json({ success: true, count: (data || []).length, rows: data || [] });
  } catch (err) {
    console.error('GET /api/sessions/status gagal:', err.message);
    return res.status(500).json({ success: false, message: 'Gagal memuat sesi.' });
  }
});

app.post('/api/licenses', requireFirebaseAdmin, async (req, res) => {
  try {
    const rows = req.body && req.body.rows;

    if (!Array.isArray(rows) || rows.length === 0 || rows.length > 50) {
      return res.status(400).json({
        success: false,
        message: 'Data lisensi tidak valid (maksimal 50)'
      });
    }

    const cleanRows = rows.map((row) => ({
      key: String(row.key || '').trim(),
      project: String(row.project || '').trim(),
      generated_by: req.verifiedAdmin.username || req.verifiedAdmin.uid,
      active: true,
      used: false,
      status: 'unused',
      expires_at: row.expires_at || null
    }));

    if (cleanRows.some((row) => !row.key || !row.project)) {
      return res.status(400).json({
        success: false,
        message: 'Key dan project wajib diisi'
      });
    }

    const { error } = await supabaseAdmin
      .from('licenses')
      .insert(cleanRows);

    if (error) {
     console.error('Insert licenses gagal:', {
       message: error.message,
       code: error.code,
       details: error.details,
       hint: error.hint
  });

  return res.status(500).json({
    success: false,
    message: 'Gagal menyimpan lisensi ke Supabase'
  });
}

    return res.json({
      success: true,
      count: cleanRows.length
    });
  } catch (err) {
    console.error('POST /api/licenses gagal:', err.message);
    return res.status(500).json({
      success: false,
      message: 'Terjadi kesalahan pada server'
    });
  }
});



/* Reset penggunaan lisensi dari panel admin. */
app.post('/api/licenses/reset-usage', requireFirebaseAdmin, async (req, res) => {
  try {
    const key = String(req.body?.key || '').trim();
    if (!key) return res.status(400).json({ success: false, message: 'Key lisensi wajib diisi.' });
    const { data, error } = await supabaseAdmin
      .from('licenses')
      .update({ used: false, device_id: null, used_at: null, status: 'unused' })
      .eq('key', key)
      .select('key');
    if (error) {
      console.error('Reset penggunaan lisensi gagal:', error.message);
      return res.status(502).json({ success: false, message: 'Gagal mereset lisensi di Supabase.' });
    }
    if (!data || !data.length) return res.status(404).json({ success: false, message: 'Key tidak ditemukan di Supabase.' });
    return res.json({ success: true, count: data.length });
  } catch (err) {
    console.error('POST /api/licenses/reset-usage gagal:', err.message);
    return res.status(500).json({ success: false, message: 'Terjadi kesalahan pada server.' });
  }
});

/* Tandai lisensi sebagai sudah digunakan setelah produk terkirim. */
app.post('/api/licenses/mark-used', requireFirebaseAdmin, async (req, res) => {
  try {
    const key = String(req.body?.key || '').trim();
    if (!key) return res.status(400).json({ success: false, message: 'Key lisensi wajib diisi.' });
    const { data, error } = await supabaseAdmin
      .from('licenses')
      .update({ used: true, used_at: new Date().toISOString(), status: 'used' })
      .eq('key', key)
      .select('key');
    if (error) {
      console.error('Mark-used lisensi gagal:', error.message);
      return res.status(502).json({ success: false, message: 'Gagal memperbarui status lisensi di Supabase.' });
    }
    if (!data || !data.length) return res.status(404).json({ success: false, message: 'Key tidak ditemukan di Supabase.' });
    return res.json({ success: true, count: data.length });
  } catch (err) {
    console.error('POST /api/licenses/mark-used gagal:', err.message);
    return res.status(500).json({ success: false, message: 'Terjadi kesalahan pada server.' });
  }
});


/* Sinkronisasi lisensi lama melalui backend; tidak menerima kredensial Supabase dari browser. */
app.post('/api/licenses/sync', requireFirebaseAdmin, async (req, res) => {
  try {
    const rows = req.body && req.body.rows;
    if (!Array.isArray(rows) || rows.length === 0 || rows.length > 500)
      return res.status(400).json({ success: false, message: 'Data lisensi tidak valid (maksimal 500).' });
    const cleanRows = rows.map((row) => ({
      key: String(row.key || '').trim(),
      project: String(row.project || '').trim(),
      active: row.active !== false,
      used: row.used === true,
      device_id: row.device_id || null,
      generated_by: String(row.generated_by || req.verifiedAdmin.username || req.verifiedAdmin.uid),
      expires_at: row.expires_at || null,
      used_at: row.used_at || null,
      status: row.active === false ? 'revoked' : (row.used === true ? 'used' : 'unused')
    }));
    if (cleanRows.some((row) => !row.key || !row.project))
      return res.status(400).json({ success: false, message: 'Setiap lisensi wajib memiliki key dan project.' });
    const { error } = await supabaseAdmin.from('licenses').upsert(cleanRows, { onConflict: 'key' });
    if (error) {
      console.error('Sinkronisasi lisensi gagal:', error.message);
      return res.status(502).json({ success: false, message: 'Gagal menyinkronkan lisensi ke Supabase.' });
    }
    return res.json({ success: true, count: cleanRows.length });
  } catch (err) {
    console.error('POST /api/licenses/sync gagal:', err.message);
    return res.status(500).json({ success: false, message: 'Terjadi kesalahan pada server.' });
  }
});

app.post('/api/licenses/revoke', requireFirebaseAdmin, async (req, res) => {
  try {
    const key = String(req.body?.key || '').trim();

    if (!key) {
      return res.status(400).json({
        success: false,
        message: 'Key lisensi wajib diisi'
      });
    }

    const { data, error } = await supabaseAdmin
      .from('licenses')
      .update({
        active: false,
        status: 'revoked'
      })
      .eq('key', key)
      .select('key');

    if (error) {
      console.error('Revoke license gagal:', {
        message: error.message,
        code: error.code,
        details: error.details,
        hint: error.hint
      });

      return res.status(500).json({
        success: false,
        message: 'Gagal revoke lisensi di Supabase'
      });
    }

    if (!data || data.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Key tidak ditemukan di Supabase'
      });
    }

    return res.json({
      success: true,
      count: data.length
    });
  } catch (err) {
    console.error('POST /api/licenses/revoke gagal:', err.message);

    return res.status(500).json({
      success: false,
      message: 'Terjadi kesalahan pada server'
    });
  }
});

// Aktivasi lisensi dari APK
app.post('/api/licenses/activate', activationLimiter, async (req, res) => {
  try {
    const key = String(req.body?.key || '').trim().toUpperCase();
    const deviceId = String(req.body?.device_id || '').trim();
    const nexusId = String(req.body?.nexus_id || '').trim();

    if (!key || !deviceId || !nexusId) {
      return res.status(400).json({
        success: false,
        code: 'invalid_input',
        message: 'Key, device_id, dan nexus_id wajib diisi'
      });
    }

    if (key.length > 200 || deviceId.length > 300 || nexusId.length > 300) {
      return res.status(400).json({
        success: false,
        code: 'invalid_input',
        message: 'Input terlalu panjang'
      });
    }

    const { data, error } = await supabaseAdmin.rpc('activate_license', {
      p_key: key,
      p_device_id: deviceId,
      p_nexus_id: nexusId
    });

    if (error) {
      console.error('Aktivasi lisensi gagal:', {
        message: error.message,
        code: error.code
      });

      return res.status(500).json({
        success: false,
        message: 'Gagal memproses aktivasi lisensi'
      });
    }

    const result = typeof data === 'string' ? JSON.parse(data) : data;

    if (!result || result.success !== true) {
      const codes = {
        invalid_input: 400,
        not_found: 404,
        revoked: 403,
        expired: 403,
        already_bound: 409,
        invalid_expiry: 500
      };

      const code = result?.code || 'activation_failed';

      return res.status(codes[code] || 400).json({
        success: false,
        code
      });
    }

    return res.json({
      success: true,
      nexus_id: result.nexus_id
    });
  } catch (err) {
    console.error('POST /api/licenses/activate gagal:', err.message);

    return res.status(500).json({
      success: false,
      message: 'Terjadi kesalahan pada server'
    });
  }
});

app.post('/api/licenses/check', activationLimiter, async (req, res) => {
  try {
    const key = String(req.body?.key || '').trim().toUpperCase();
    const deviceId = String(req.body?.device_id || '').trim();

    if (!key || !deviceId) {
      return res.status(400).json({
        success: false,
        code: 'invalid_input'
      });
    }

    if (key.length > 200 || deviceId.length > 300) {
      return res.status(400).json({
        success: false,
        code: 'invalid_input'
      });
    }

    const { data, error } = await supabaseAdmin.rpc('check_license', {
      p_key: key,
      p_device_id: deviceId
    });

    if (error) {
      console.error('Pemeriksaan lisensi gagal:', {
        message: error.message,
        code: error.code
      });

      return res.status(500).json({
        success: false,
        code: 'server_error'
      });
    }

    const result = typeof data === 'string' ? JSON.parse(data) : data;

    if (!result || result.success !== true) {
      const code = result?.code || 'check_failed';
      const statusCodes = {
        invalid_input: 400,
        not_found: 404,
        revoked: 403,
        expired: 403,
        already_bound: 409,
        invalid_expiry: 500
      };

      return res.status(statusCodes[code] || 400).json({
        success: false,
        code
      });
    }

    return res.json({
      success: true,
      nexus_id: result.nexus_id || ''
    });
  } catch (err) {
    console.error('POST /api/licenses/check gagal:', err.message);

    return res.status(500).json({
      success: false,
      code: 'server_error'
    });
  }
});

app.post('/api/licenses/session', activationLimiter, async (req, res) => {
  try {
    const key = String(req.body?.key || '').trim().toUpperCase();
    const deviceId = String(req.body?.device_id || '').trim();

    if (!key || !deviceId || key.length > 200 || deviceId.length > 300) {
      return res.status(400).json({
        success: false,
        code: 'invalid_input'
      });
    }

    // Pastikan lisensi masih valid untuk perangkat ini.
    const { data: checkData, error: checkError } =
      await supabaseAdmin.rpc('check_license', {
        p_key: key,
        p_device_id: deviceId
      });

    if (checkError) {
      console.error('Pemeriksaan sesi gagal:', checkError.message);
      return res.status(500).json({
        success: false,
        code: 'server_error'
      });
    }

    const checked = typeof checkData === 'string'
      ? JSON.parse(checkData)
      : checkData;

    if (!checked || checked.success !== true) {
      return res.status(403).json({
        success: false,
        code: checked?.code || 'license_invalid'
      });
    }

    // Cari sesi yang sudah ada.
    const { data: rows, error: findError } = await supabaseAdmin
      .from('sessions')
      .select('id')
      .eq('key', key)
      .limit(1);

    if (findError) {
      console.error('Pencarian sesi gagal:', findError.message);
      return res.status(500).json({
        success: false,
        code: 'session_update_failed'
      });
    }

    const sessionData = {
      platform: 'nexus_android',
      online: true,
      last_seen: new Date().toISOString()
    };

    let sessionResult;

    if (rows && rows.length > 0) {
      sessionResult = await supabaseAdmin
        .from('sessions')
        .update(sessionData)
        .eq('id', rows[0].id);
    } else {
      sessionResult = await supabaseAdmin
        .from('sessions')
        .insert({ key, ...sessionData });
    }

    if (sessionResult.error) {
      console.error('Pembaruan sesi gagal:', sessionResult.error.message);
      return res.status(500).json({
        success: false,
        code: 'session_update_failed'
      });
    }

    return res.json({ success: true });
  } catch (err) {
    console.error('POST /api/licenses/session gagal:', err.message);
    return res.status(500).json({
      success: false,
      code: 'server_error'
    });
  }
});

async function verifyAdminPassword(password, stored) {
  if (typeof stored !== 'string' || !stored) return false;
  if (stored.startsWith('scrypt$')) {
    const parts = stored.split('$');
    if (parts.length !== 3 || !/^[a-f0-9]{32}$/i.test(parts[1]) || !/^[a-f0-9]{128}$/i.test(parts[2])) return false;
    const key = await scryptAsync(String(password), parts[1], 64);
    return safeEqual(Buffer.from(key).toString('hex'), parts[2]);
  }
  return safeEqual(stored, legacySimpleHash(String(password)));
}

async function requireFirebaseAdmin(req, res, next) {
  const header = req.headers.authorization || '';
  if (!header.startsWith('Bearer ')) {
    return res.status(401).json({ success:false, message:'Token autentikasi diperlukan' });
  }
  const bearer=header.slice(7).trim();
  const session=verifyAdminSession(bearer);
  if(session){
    // Sesi bertanda tangan tidak otomatis tetap sah setelah admin dihapus/dinonaktifkan.
    // Cocokkan setiap permintaan dengan profil admin yang masih ada di Supabase.
    try {
      const { data: activeAdmin, error: sessionLookupError } = await supabaseAdmin
        .from('admins')
        .select('id,username,name,role')
        .eq('username', String(session.username || '').trim().toLowerCase())
        .maybeSingle();
      if (sessionLookupError) {
        console.error('[Auth] Gagal memeriksa sesi admin backend:', sessionLookupError.code || sessionLookupError.message);
        return res.status(503).set('Cache-Control','no-store').json({
          success:false, code:'ADMIN_STORE_UNAVAILABLE',
          message:'Verifikasi sesi admin sementara tidak tersedia.'
        });
      }
      if (!activeAdmin ||
          String(activeAdmin.id) !== String(session.uid) ||
          !['owner','admin'].includes(activeAdmin.role) ||
          activeAdmin.role !== session.role) {
        return res.status(403).set('Cache-Control','no-store').json({
          success:false, code:'ADMIN_SESSION_REVOKED',
          message:'Sesi admin sudah tidak berlaku. Silakan login ulang.'
        });
      }
      req.verifiedAdmin={
        uid:String(activeAdmin.id),
        username:activeAdmin.username,
        name:activeAdmin.name||activeAdmin.username,
        role:activeAdmin.role,
        authMode:'backend'
      };
      return next();
    } catch (err) {
      console.error('[Auth] Pemeriksaan sesi admin backend gagal:', err.message);
      return res.status(503).set('Cache-Control','no-store').json({
        success:false, code:'ADMIN_STORE_UNAVAILABLE',
        message:'Verifikasi sesi admin sementara tidak tersedia.'
      });
    }
  }
  let decoded;
  try {
    decoded = await admin.auth().verifyIdToken(bearer);
  } catch (err) {
    console.warn('[Auth] Bearer token ditolak:', err.code || err.message);
    return res.status(401).json({
      success:false, code:'INVALID_AUTH_TOKEN',
      message:'Sesi autentikasi tidak valid atau kedaluwarsa. Silakan login ulang.'
    });
  }

  // Emergency migration path: explicit server-side UID allowlist avoids Firestore reads.
  // Configure ADMIN_UID_ALLOWLIST in Railway with comma-separated trusted Firebase UIDs.
  const allowedOwnerUids = (process.env.ADMIN_UID_ALLOWLIST || '')
    .split(',')
    .map((uid) => uid.trim())
    .filter(Boolean);

  if (allowedOwnerUids.includes(decoded.uid)) {
    const email = String(decoded.email || '');
    req.verifiedAdmin = {
      uid: decoded.uid,
      username: email ? email.split('@')[0] : decoded.uid,
      name: decoded.name || email || 'Owner',
      role: 'owner'
    };
    return next();
  }

  const emailUsername = String(decoded.email || '').split('@')[0].trim().toLowerCase();
  if (!emailUsername) {
    return res.status(403).json({ success:false, code:'NOT_ADMIN', message:'Akun Firebase ini belum terdaftar sebagai admin di Supabase.' });
  }
  let adminData;
  try {
    const { data, error } = await supabaseAdmin.from('admins')
      .select('id,username,name,role,created_at,avatar_url')
      .eq('username', emailUsername).maybeSingle();
    if (error) throw error;
    adminData = data;
  } catch (err) {
    console.error('[Auth] Gagal membaca admin dari Supabase:', err.code || err.message);
    return res.status(503).json({
      success:false, code:'ADMIN_STORE_UNAVAILABLE',
      message:'Verifikasi admin belum tersedia di Supabase. Pastikan profil admin sudah dimigrasikan.'
    });
  }
  if (!adminData) {
    return res.status(403).json({ success:false, code:'NOT_ADMIN', message:'Akun Firebase ini belum terdaftar sebagai admin di Supabase.' });
  }
  if (!['owner', 'admin'].includes(adminData.role)) {
    return res.status(403).json({
      success: false,
      code: 'ADMIN_ROLE_DENIED',
      message: 'Akses admin ditolak.'
    });
  }

  req.verifiedAdmin = {
    uid: decoded.uid,
    username: adminData.username,
    name: adminData.name,
    role: adminData.role
  };

  next();
}

/* ── Start ── */
app.listen(PORT, () => {
  console.log('\n╔═══════════════════════════════════════════╗');
  console.log('║  MDZZXITERS Backend v3.1  →  port ' + PORT + '    ║');
  console.log('╠═══════════════════════════════════════════╣');
  console.log('║  Supabase  : ' + (SUPABASE_URL ? '✓ connected' : '✗ NOT SET'));
  console.log('║  Brevo API : ' + (BREVO_API_KEY ? '✓ configured' : '✗ NOT SET'));
  console.log('║  From      : ' + FROM_EMAIL);
  console.log('║  Bucket    : ' + BUCKET);
  console.log('╚═══════════════════════════════════════════╝\n');
});
