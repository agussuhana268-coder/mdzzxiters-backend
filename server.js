/**
 * MDZZXITERS — Product Delivery Backend v2.1
 * Stack: Express · Supabase Storage · Brevo SMTP (Nodemailer)
 * ──────────────────────────────────────────────────────────
 * Endpoints:
 *   GET    /api/health             → server health check
 *   GET    /api/products           → list .zip files di bucket
 *   POST   /api/upload-product     → upload .zip ke Supabase Storage
 *   DELETE /api/products/:file     → hapus file dari bucket
 *   POST   /api/send-product       → signed URL + kirim email Brevo
 */

'use strict';
require('dotenv').config();

const express    = require('express');
const cors       = require('cors');
const multer     = require('multer');
const path       = require('path');
const nodemailer = require('nodemailer');
const { createClient } = require('@supabase/supabase-js');

/* ══ CONFIG ══ */
const PORT          = process.env.PORT || process.env.RAILWAY_PORT || 3000;
const SUPABASE_URL  = (process.env.SUPABASE_URL || '').replace('/rest/v1/','').replace(/\/$/,'');
/* Auto-select valid Supabase key — skip placeholder text */
function pickSupabaseKey() {
  const svc  = process.env.SUPABASE_SERVICE_KEY || '';
  const anon = process.env.SUPABASE_ANON_KEY    || '';
  // Valid Supabase JWT always starts with 'eyJ'
  if (svc.startsWith('eyJ'))  return svc;
  if (anon.startsWith('eyJ')) return anon;
  return svc || anon;
}
const SUPABASE_KEY = pickSupabaseKey();
const BUCKET        = 'products';
const SIGNED_EXPIRY = 900; // 15 menit

const BREVO_HOST = process.env.BREVO_SMTP_HOST || 'smtp-relay.brevo.com';
const BREVO_PORT = parseInt(process.env.BREVO_SMTP_PORT) || 587;
const BREVO_USER = process.env.BREVO_SMTP_USER;
const BREVO_PASS = process.env.BREVO_SMTP_PASS;
const FROM_NAME  = process.env.FROM_NAME  || 'MDZZXITERS Team';
const FROM_EMAIL = process.env.FROM_EMAIL || BREVO_USER;
const ADMIN_KEY  = process.env.ADMIN_SECRET || 'mdzz_admin_2024';

/* ══ SUPABASE ══ */
const supabase = createClient(SUPABASE_URL, SUPABASE_KEY, {
  auth: { persistSession: false }
});

/* ══ BREVO SMTP TRANSPORTER ══ */
const transporter = nodemailer.createTransport({
  host:   BREVO_HOST,
  port:   BREVO_PORT,
  secure: false, // STARTTLS
  auth: {
    user: BREVO_USER,
    pass: BREVO_PASS
  }
});

/* ══ APP ══ */
const app = express();
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 200 * 1024 * 1024 }, // 200 MB
  fileFilter: (_, file, cb) => {
    path.extname(file.originalname).toLowerCase() === '.zip'
      ? cb(null, true)
      : cb(new Error('Hanya file .zip yang diizinkan'));
  }
});

/* ── CORS: allow all origins including mobile browsers ── */
app.use(cors({
  origin: '*',
  methods: ['GET','POST','PUT','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','X-Admin-Key','Authorization'],
  credentials: false
}));
app.options('*', cors()); // Handle preflight for all routes
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

/* ── Auth middleware ── */
function requireAuth(req, res, next) {
  if (req.headers['x-admin-key'] !== ADMIN_KEY) {
    return res.status(401).json({ success: false, message: 'Unauthorized — cek Admin Key' });
  }
  next();
}

/* ══════════════════════════
   GET /api/health
══════════════════════════ */
app.get('/api/health', async (_, res) => {
  res.header('Access-Control-Allow-Origin', '*');
  const svcKey  = process.env.SUPABASE_SERVICE_KEY || '';
  const keyType = svcKey.startsWith('eyJ') ? 'service_role' : 'anon';
  
  /* Test bucket access */
  let bucketOk = false, bucketErr = null;
  try {
    const { data, error } = await supabase.storage.from(BUCKET).list('', { limit: 1 });
    bucketOk = !error;
    if (error) bucketErr = error.message;
  } catch (e) { bucketErr = e.message; }

  res.json({
    success:   true,
    status:    'online',
    supabase:  !!(SUPABASE_URL && SUPABASE_KEY),
    keyType:   keyType,
    bucket:    bucketOk ? 'accessible' : ('ERROR: ' + bucketErr),
    brevo:     !!(BREVO_USER && BREVO_PASS),
    timestamp: new Date().toISOString()
  });
});

/* ══════════════════════════
   GET /api/products
   List semua .zip di bucket
══════════════════════════ */
app.get('/api/products', requireAuth, async (_, res) => {
  try {
    const { data, error } = await supabase.storage
      .from(BUCKET)
      .list('', { limit: 200, sortBy: { column: 'name', order: 'asc' } });

    if (error) throw error;

    const files = (data || [])
      .filter(f => f.name && f.name.endsWith('.zip'))
      .map(f => ({
        name:      f.name,
        size:      f.metadata?.size || 0,
        updatedAt: f.updated_at || f.created_at || null
      }));

    res.json({ success: true, files });
  } catch (e) {
    console.error('[products]', e.message);
    res.status(500).json({ success: false, message: e.message });
  }
});

/* ══════════════════════════
   POST /api/upload-product
   Upload .zip ke Supabase
══════════════════════════ */
app.post('/api/upload-product', requireAuth, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ success: false, message: 'Tidak ada file' });

    const raw  = (req.body.fileName || req.file.originalname).trim();
    const safe = raw.toLowerCase().replace(/\s+/g, '-').replace(/[^a-z0-9._-]/g, '');
    const dest = safe.endsWith('.zip') ? safe : safe + '.zip';

    const { error } = await supabase.storage
      .from(BUCKET)
      .upload(dest, req.file.buffer, { contentType: 'application/zip', upsert: true });

    if (error) throw error;

    console.log(`[upload] OK → ${dest} (${(req.file.size / 1048576).toFixed(2)} MB)`);
    res.json({
      success: true,
      message: `"${dest}" berhasil diunggah ke bucket "${BUCKET}"`,
      path: dest,
      size: req.file.size
    });
  } catch (e) {
    console.error('[upload]', e.message);
    res.status(500).json({ success: false, message: e.message });
  }
});

/* ══════════════════════════
   DELETE /api/products/:fn
══════════════════════════ */
app.delete('/api/products/:fn', requireAuth, async (req, res) => {
  try {
    const fn = decodeURIComponent(req.params.fn);
    const { error } = await supabase.storage.from(BUCKET).remove([fn]);
    if (error) throw error;
    console.log(`[delete] OK → ${fn}`);
    res.json({ success: true, message: `"${fn}" berhasil dihapus` });
  } catch (e) {
    console.error('[delete]', e.message);
    res.status(500).json({ success: false, message: e.message });
  }
});

/* ══════════════════════════
   POST /api/send-product
   1. Buat Signed URL (15 mnt)
   2. Kirim email via Brevo
══════════════════════════ */
app.post('/api/send-product', requireAuth, async (req, res) => {
  const { buyerEmail, productName, licenseKey, fileName } = req.body;

  if (!buyerEmail || !productName || !licenseKey || !fileName) {
    return res.status(400).json({
      success: false,
      message: 'buyerEmail, productName, licenseKey, dan fileName wajib diisi'
    });
  }

  try {
    /* ── STEP 1: Signed URL dari Supabase Storage ── */
    const { data: sd, error: se } = await supabase.storage
      .from(BUCKET)
      .createSignedUrl(fileName, SIGNED_EXPIRY);

    if (se) throw new Error('Supabase Storage: ' + se.message);

    const downloadUrl = sd.signedUrl;
    const expireDate  = new Date(Date.now() + SIGNED_EXPIRY * 1000);
    const expireStr   = expireDate.toLocaleString('id-ID', {
      day: '2-digit', month: 'long', year: 'numeric',
      hour: '2-digit', minute: '2-digit',
      timeZone: 'Asia/Jakarta'
    }) + ' WIB';

    /* ── STEP 2: Kirim email via Brevo SMTP ── */
    const info = await transporter.sendMail({
      from:    `"${FROM_NAME}" <${FROM_EMAIL}>`,
      to:      buyerEmail,
      subject: `[MDZZXITERS] Produk Anda: ${productName}`,
      html:    buildEmailHtml({ buyerEmail, productName, licenseKey, downloadUrl, expireStr }),
      text:    `Produk: ${productName}\nLicense: ${licenseKey}\nDownload: ${downloadUrl}\nExpired: ${expireStr}`
    });

    console.log(`[send] OK → ${buyerEmail} | msgId: ${info.messageId}`);
    res.json({
      success:   true,
      message:   `Email berhasil dikirim ke ${buyerEmail}`,
      messageId: info.messageId,
      expiresAt: expireStr
    });

  } catch (e) {
    console.error('[send]', e.message);
    res.status(500).json({ success: false, message: e.message });
  }
});

/* ══ EMAIL HTML TEMPLATE ══ */
function buildEmailHtml({ buyerEmail, productName, licenseKey, downloadUrl, expireStr }) {
  return `<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>${productName} — MDZZXITERS</title>
</head>
<body style="margin:0;padding:0;background:#0a0f1e;font-family:'Segoe UI',Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#0a0f1e;padding:36px 16px;">
<tr><td align="center">
<table width="100%" style="max-width:540px;background:#0d1628;border-radius:20px;overflow:hidden;border:1px solid rgba(56,189,248,.18);">

  <!-- HEADER -->
  <tr>
    <td style="background:linear-gradient(135deg,#1e3a8a 0%,#1d4ed8 55%,#0ea5e9 100%);padding:36px 32px 28px;text-align:center;">
      <div style="width:58px;height:58px;border-radius:50%;background:rgba(255,255,255,.15);
                  line-height:58px;font-size:24px;font-weight:900;color:#fff;
                  font-family:'Courier New',monospace;margin:0 auto 14px;display:inline-block;">M</div>
      <h1 style="margin:0;color:#fff;font-size:21px;font-weight:700;letter-spacing:1.5px;">MDZZXITERS</h1>
      <p style="margin:6px 0 0;color:rgba(255,255,255,.65);font-size:11px;letter-spacing:2.5px;">PRODUK SIAP DIUNDUH</p>
    </td>
  </tr>

  <!-- BODY -->
  <tr><td style="padding:30px 30px 22px;">
    <p style="margin:0 0 22px;color:#94a3b8;font-size:13px;line-height:1.6;">
      Halo! Terima kasih telah membeli produk kami.<br/>
      Berikut adalah detail lisensi dan tautan unduhan Anda.
    </p>

    <!-- Nama Produk -->
    <table width="100%" style="background:rgba(56,189,248,.06);border:1px solid rgba(56,189,248,.16);border-radius:12px;margin-bottom:12px;">
      <tr><td style="padding:18px 20px;">
        <div style="font-size:10px;color:#475569;letter-spacing:2.5px;font-family:monospace;margin-bottom:5px;">NAMA PRODUK</div>
        <div style="font-size:19px;font-weight:700;color:#e2f4ff;">${productName}</div>
      </td></tr>
    </table>

    <!-- License Key -->
    <table width="100%" style="background:rgba(16,185,129,.06);border:1px solid rgba(16,185,129,.2);border-radius:12px;margin-bottom:20px;">
      <tr><td style="padding:18px 20px;">
        <div style="font-size:10px;color:#475569;letter-spacing:2.5px;font-family:monospace;margin-bottom:7px;">LICENSE KEY</div>
        <div style="font-size:17px;font-weight:700;color:#34d399;font-family:'Courier New',monospace;letter-spacing:2px;word-break:break-all;">${licenseKey}</div>
      </td></tr>
    </table>

    <!-- Tombol Download -->
    <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:16px;">
      <tr><td align="center">
        <a href="${downloadUrl}"
           style="display:inline-block;
                  background:linear-gradient(135deg,#1e3a8a,#2563eb,#0ea5e9);
                  color:#fff;text-decoration:none;font-weight:700;font-size:15px;
                  padding:17px 48px;border-radius:12px;letter-spacing:.5px;">
          &#11015;&#65039;&nbsp; UNDUH PRODUK SEKARANG
        </a>
      </td></tr>
    </table>

    <!-- Expiry Warning -->
    <table width="100%" style="background:rgba(245,158,11,.07);border:1px solid rgba(245,158,11,.18);border-radius:11px;margin-bottom:24px;">
      <tr><td style="padding:13px 18px;">
        <p style="margin:0;color:#fbbf24;font-size:12px;font-family:monospace;line-height:1.7;">
          &#9201; Link unduhan <strong>kedaluwarsa dalam 15 menit</strong><br/>
          Batas waktu: <strong>${expireStr}</strong>
        </p>
      </td></tr>
    </table>

    <p style="margin:0;color:#334155;font-size:12px;line-height:1.7;">
      Simpan license key di tempat aman.<br/>
      Jika link sudah kedaluwarsa, hubungi admin untuk mendapatkan link baru.
    </p>
  </td></tr>

  <!-- FOOTER -->
  <tr>
    <td style="background:rgba(0,0,0,.28);padding:18px 30px;text-align:center;border-top:1px solid rgba(56,189,248,.07);">
      <p style="margin:0;color:#1e3a5a;font-size:10px;font-family:monospace;letter-spacing:1px;">
        MDZZXITERS CORPORATION &middot; AUTOMATED DELIVERY SYSTEM<br/>
        Pesan ini dikirim otomatis &mdash; jangan dibalas.
      </p>
    </td>
  </tr>

</table>
</td></tr>
</table>
</body>
</html>`;
}

/* ── Error handler ── */
app.use((err, _, res, __) => {
  if (err.code === 'LIMIT_FILE_SIZE')
    return res.status(413).json({ success: false, message: 'File terlalu besar (max 200MB)' });
  res.status(500).json({ success: false, message: err.message });
});

/* ── Start server ── */
app.listen(PORT, () => {
  console.log('\n╔════════════════════════════════════════╗');
  console.log(`║  MDZZXITERS Backend  →  port ${PORT}      ║`);
  console.log('╠════════════════════════════════════════╣');
  const keyType = (process.env.SUPABASE_SERVICE_KEY||'').startsWith('eyJ') ? 'service_role' : 'anon';
  console.log(`║  Supabase  : ${SUPABASE_URL ? '✓ connected (' + keyType + ' key)' : '✗ NOT SET'}`);
  console.log(`║  Brevo     : ${BREVO_USER   ? '✓ ' + BREVO_USER.substring(0,22) : '✗ NOT SET'}`);
  console.log(`║  Bucket    : ${BUCKET}`);
  console.log(`║  From      : ${FROM_EMAIL}`);
  console.log('╚════════════════════════════════════════╝\n');
});
