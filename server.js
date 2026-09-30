// Glass Engine backend - Render (Node + Express)
// Deploy: GitHub repo -> render.com -> New Web Service (Free)
//   Build: npm install | Start: npm start | Health check: /health
//
// Routes:
//   POST /auth/api/2.0  <- auth (dual protocol)
//   GET  /sock/:file     <- file host (replaces keypanel.tech)
//   GET  /health
//
// Protocol A (OLD native client, Login.h - encrypted):
//   Req:  { "data": base64( xor( '{"license_key":..,"hwid":..,"game_type":"PUBG","version":"1.0"}', KEY ) ) }
//   Resp: { "data": base64( xor( '{"status":"success","data":{...}}', KEY ) ) }
//   KEY = "JiM21rNU12eERlNmpqa3FuQks" (must match Login.h oxorany(...))
//
// Protocol B (plain JSON): Req { license_key, hwid, game_type, version } -> Resp { status, data }
//
// NOTE (Render Free): filesystem ephemeral - restart/redeploy hole licenses.json-er
// HWID lock reset hoye jabe (sob device abar bind hobe). Permanent DB lagle pore
// Supabase Postgres lagano jabe.

const express = require('express');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(express.json({ limit: '1mb' }));

const PORT = process.env.PORT || 3000;
const APP_VERSION = '1.0'; // must match Login.h version, else "Your version is old"
const ENCRYPTION_KEY = 'JiM21rNU12eERlNmpqa3FuQks'; // must match Login.h
const LICENSES_FILE = path.join(__dirname, 'licenses.json');
const FILES_DIR = path.join(__dirname, 'files');

if (!fs.existsSync(FILES_DIR)) fs.mkdirSync(FILES_DIR, { recursive: true });
if (!fs.existsSync(LICENSES_FILE)) {
  fs.writeFileSync(LICENSES_FILE, JSON.stringify({
    // demo key - nijer key ekhane add koro
    'TEST-KEY-123': { expiry_date: '2027-12-31', max_devices: 1, hwid: null, active_devices: 0 }
  }, null, 2));
}

// ---------- XOR + base64 (byte-identical to Login.h) ----------
function xorCrypt(dataBuf, keyBuf) {
  const out = Buffer.allocUnsafe(dataBuf.length);
  for (let i = 0; i < dataBuf.length; i++) out[i] = dataBuf[i] ^ keyBuf[i % keyBuf.length];
  return out;
}
function encryptData(obj) {
  const json = typeof obj === 'string' ? obj : JSON.stringify(obj);
  const x = xorCrypt(Buffer.from(json, 'utf8'), Buffer.from(ENCRYPTION_KEY, 'utf8'));
  return { data: x.toString('base64') };
}
function decryptData(b64) {
  const raw = Buffer.from(String(b64 || ''), 'base64');
  const x = xorCrypt(raw, Buffer.from(ENCRYPTION_KEY, 'utf8'));
  return JSON.parse(x.toString('utf8'));
}

// ---------- license store (licenses.json) ----------
function loadLicenses() {
  try { return JSON.parse(fs.readFileSync(LICENSES_FILE, 'utf8')); }
  catch { return {}; }
}
function saveLicenses(db) {
  try { fs.writeFileSync(LICENSES_FILE, JSON.stringify(db, null, 2)); } catch {}
}

function doAuth({ license_key, hwid, game_type, version }, db) {
  if (!license_key) return { status: 'error', message: 'Missing license_key', _save: false };
  if (version && version !== APP_VERSION) {
    return { status: 'success', data: { expiry_date: '', version: APP_VERSION, max_devices: 0, active_devices: 0 }, _save: false };
  }
  const lic = db[license_key];
  if (!lic) return { status: 'error', message: 'Invalid license key', _save: false };
  if (!lic.hwid && hwid) { lic.hwid = hwid; lic.active_devices = 1; return success(lic, true); }
  if (lic.hwid && hwid && lic.hwid !== hwid) {
    return { status: 'error', message: 'Key already used on another device', _save: false };
  }
  return success(lic, false);
}
function success(lic, save) {
  return {
    status: 'success',
    data: {
      expiry_date: lic.expiry_date || '2027-12-31',
      version: APP_VERSION,
      max_devices: lic.max_devices || 1,
      active_devices: lic.active_devices || 1
    },
    _save: save
  };
}

app.get('/health', (req, res) => res.json({ ok: true, version: APP_VERSION }));

app.post('/auth/api/2.0', (req, res) => {
  const db = loadLicenses();
  // Protocol A: old encrypted client { data: "base64..." }
  if (req.body && req.body.data && !req.body.license_key) {
    let payload;
    try { payload = decryptData(req.body.data); }
    catch { return res.json(encryptData({ status: 'error', message: 'Bad encrypted payload' })); }
    const { _save, ...result } = doAuth(payload || {}, db);
    if (_save) saveLicenses(db);
    return res.json(encryptData(result)); // client decrypts this
  }
  // Protocol B: plain JSON
  const { _save, ...result } = doAuth(req.body || {}, db);
  if (_save) saveLicenses(db);
  return res.json(result);
});

// --- SOCK FILE HOST ---
function checkFileAuth(req) {
  const hdr = req.headers['x-license'] || req.headers['x-key'] || req.headers['license'] || '';
  const auth = req.headers['authorization'] || '';
  const key = hdr || String(auth).replace(/^Bearer\s+/i, '') || req.query.key || '';
  if (!key) return false;
  const db = loadLicenses();
  return !!db[String(key)];
}

app.get('/sock/:file', (req, res) => {
  if (!checkFileAuth(req)) return res.status(401).json({ error: 'Invalid license' });
  const name = path.basename(req.params.file || '');
  if (!name || !/\.zip$/i.test(name)) return res.status(400).json({ error: 'Only .zip allowed' });
  const f = path.join(FILES_DIR, name);
  if (!fs.existsSync(f)) return res.status(404).json({ error: 'File not found on server. Put zip in ./files/' });
  res.download(f);
});

app.listen(PORT, () => {
  console.log(`Glass-Server running on port ${PORT}`);
  console.log(`Auth: POST /auth/api/2.0 | Files: GET /sock/<name>.zip (put zips in ./files/)`);
});
