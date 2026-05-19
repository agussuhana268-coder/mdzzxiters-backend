/**
 * MDZZXITERS — Product Delivery Backend v3.1
 * Stack: Express · Supabase Storage · Brevo HTTP API
 */
'use strict';
require('dotenv').config();

const express = require('express');
const cors    = require('cors');
const multer  = require('multer');
const path    = require('path');
const https   = require('https');
const { createClient } = require('@supabase/supabase-js');

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
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 200 * 1024 * 1024 },
  fileFilter: (_, file, cb) => {
    path.extname(file.originalname).toLowerCase() === '.zip'
      ? cb(null, true) : cb(new Error('Hanya .zip'));
  }
});

app.use(cors({ origin: '*', methods: ['GET','POST','PUT','DELETE','OPTIONS'], allowedHeaders: ['Content-Type','X-Admin-Key','Authorization'] }));
app.options('*', cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

function requireAuth(req, res, next) {
  if (req.headers['x-admin-key'] !== ADMIN_KEY)
    return res.status(401).json({ success: false, message: 'Unauthorized' });
  next();
}

/* ══ GET /download — Halaman redirect iOS-friendly ══ */
app.get('/download', (req, res) => {
  const fileUrl = req.query.url;
  if (!fileUrl || !fileUrl.startsWith('https://')) {
    return res.status(400).send('<h2>Link tidak valid atau sudah kedaluwarsa.</h2>');
  }
  // Encode untuk keamanan tampilan di HTML
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
