// Glass Engine backend - Firebase Functions (asia-south1)
// Routes (served under /api):
//   POST /api/auth/api/2.0   <- auth (dual protocol)
//   GET  /api/sock/:file      <- file host (replaces keypanel.tech)
//   GET  /api/health
//
// Protocol A (OLD native client, Login.h - encrypted):
//   Req:  { "data": base64( xor( '{"license_key":..,"hwid":..,"game_type":"PUBG","version":"1.0"}', KEY ) ) }
//   Resp: { "data": base64( xor( '{"status":"success","data":{...}}', KEY ) ) }
//   KEY = "JiM21rNU12eERlNmpqa3FuQks" (must match Login.h oxorany(...))
//
// Protocol B (NEW plain JSON - future patched client / debug):
//   Req:  { license_key, hwid, game_type, version }
//   Resp: { status, data } plain
//
// Licenses: Firestore collection "licenses" (docId = key)
//   { expiry_date: "2027-12-31", max_devices: 1, hwid: null|string, active_devices: 1 }
//   Falls back to ../licenses.json when Firestore unavailable (emulator quick-start).
// Files: Firebase Storage path "sock/<file>" (e.g. sock/pubg1.zip, sock/delta.zip)
//   Falls back to ../files/<file> when Storage object missing.

const { onRequest } = require("firebase-functions/v2/https");
const admin = require("firebase-admin");
const express = require("express");
const cors = require("cors");
const fs = require("fs");
const path = require("path");

try { admin.initializeApp(); } catch (e) { /* already init in emulator */ }

const db = (() => { try { return admin.firestore(); } catch { return null; } })();
const bucket = (() => { try { return admin.storage().bucket(); } catch { return null; } })();

const APP_VERSION = "1.0"; // must match Login.h version, else "Your version is old"
const ENCRYPTION_KEY = "JiM21rNU12eERlNmpqa3FuQks";
const LICENSES_FILE = path.join(__dirname, "..", "licenses.json");
const FILES_DIR = path.join(__dirname, "..", "files");

// ---------- XOR + base64 (byte-identical to Login.h) ----------
function xorCrypt(dataBuf, keyBuf) {
  const out = Buffer.allocUnsafe(dataBuf.length);
  for (let i = 0; i < dataBuf.length; i++) out[i] = dataBuf[i] ^ keyBuf[i % keyBuf.length];
  return out;
}
function encryptData(obj) {
  const json = typeof obj === "string" ? obj : JSON.stringify(obj);
  const x = xorCrypt(Buffer.from(json, "utf8"), Buffer.from(ENCRYPTION_KEY, "utf8"));
  return { data: x.toString("base64") };
}
function decryptData(b64) {
  const raw = Buffer.from(String(b64 || ""), "base64");
  const x = xorCrypt(raw, Buffer.from(ENCRYPTION_KEY, "utf8"));
  return JSON.parse(x.toString("utf8"));
}

// ---------- license store (Firestore primary, JSON fallback) ----------
function withTimeout(promise, ms, label) {
  let t;
  const timeout = new Promise((_, reject) => { t = setTimeout(() => reject(new Error("timeout:" + label)), ms); });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(t));
}
function loadLocalLicenses() {
  try { return JSON.parse(fs.readFileSync(LICENSES_FILE, "utf8")); }
  catch { return {}; }
}
function saveLocalLicenses(all) {
  try { fs.writeFileSync(LICENSES_FILE, JSON.stringify(all, null, 2)); } catch {}
}
async function getLicense(key) {
  if (db) {
    try {
      const snap = await withTimeout(db.collection("licenses").doc(key).get(), 4000, "firestore-get");
      if (snap.exists) return { data: snap.data(), source: "firestore" };
    } catch (e) { console.warn("firestore get failed, fallback:", e.message); }
  }
  const all = loadLocalLicenses();
  return all[key] ? { data: all[key], source: "local" } : null;
}
async function bindHwid(key, hwid) {
  if (db) {
    try { await withTimeout(db.collection("licenses").doc(key).set({ hwid, active_devices: 1 }, { merge: true }), 4000, "firestore-set"); }
    catch (e) { console.warn("firestore set failed:", e.message); }
  }
  const all = loadLocalLicenses();
  if (all[key]) { all[key].hwid = hwid; all[key].active_devices = 1; saveLocalLicenses(all); }
}

// ---------- core auth logic (shared by both protocols) ----------
async function doAuth({ license_key, hwid, game_type, version }) {
  if (!license_key) return { status: "error", message: "Missing license_key" };
  if (version && version !== APP_VERSION) {
    return { status: "success", data: { expiry_date: "", version: APP_VERSION, max_devices: 0, active_devices: 0 } };
  }
  const found = await getLicense(license_key);
  if (!found) return { status: "error", message: "Invalid license key" };
  const lic = found.data || {};
  if (!lic.hwid && hwid) await bindHwid(license_key, hwid);
  else if (lic.hwid && hwid && lic.hwid !== hwid) {
    return { status: "error", message: "Key already used on another device" };
  }
  if (lic.expiry_date && new Date(lic.expiry_date) < new Date()) {
    return { status: "error", message: "License expired: " + lic.expiry_date };
  }
  return {
    status: "success",
    data: {
      expiry_date: lic.expiry_date || "2027-12-31",
      version: APP_VERSION,
      max_devices: lic.max_devices || 1,
      active_devices: lic.active_devices || 1,
    },
  };
}

// ---------- app ----------
const app = express();
app.use(cors({ origin: true }));
app.use(express.json({ limit: "1mb" }));

app.get("/health", (req, res) => res.json({ ok: true, version: APP_VERSION }));

app.post("/auth/api/2.0", async (req, res) => {
  try {
    // Protocol A: old encrypted client { data: "base64..." }
    if (req.body && req.body.data && !req.body.license_key) {
      let payload;
      try { payload = decryptData(req.body.data); }
      catch { return res.json(encryptData({ status: "error", message: "Bad encrypted payload" })); }
      const result = await doAuth(payload || {});
      return res.json(encryptData(result)); // client decrypts this
    }
    // Protocol B: plain JSON
    const result = await doAuth(req.body || {});
    return res.json(result);
  } catch (e) {
    console.error("auth error:", e);
    return res.status(500).json({ status: "error", message: "Server error" });
  }
});

async function checkFileAuth(req) {
  const hdr = req.headers["x-license"] || req.headers["x-key"] || req.headers["license"] || "";
  const auth = req.headers["authorization"] || "";
  const key = hdr || String(auth).replace(/^Bearer\s+/i, "") || req.query.key || "";
  if (!key) return null;
  const found = await getLicense(String(key));
  return found ? String(key) : null;
}

app.get("/sock/:file", async (req, res) => {
  const key = await checkFileAuth(req);
  if (!key) return res.status(401).json({ error: "Invalid license" });
  const name = path.basename(req.params.file || "");
  if (!name || !/\.zip$/i.test(name)) return res.status(400).json({ error: "Only .zip allowed" });

  // 1) Firebase Storage: sock/<file>
  if (bucket) {
    try {
      const file = bucket.file("sock/" + name);
      const [exists] = await withTimeout(file.exists(), 5000, "storage-exists");
      if (exists) return await new Promise((resolve) => {
        res.setHeader("Content-Type", "application/zip");
        res.setHeader("Content-Disposition", 'attachment; filename="' + name + '"');
        file.createReadStream()
          .on("error", (e) => { console.error("storage stream:", e); if (!res.headersSent) res.status(500).json({ error: "Storage read failed" }); resolve(); })
          .on("end", () => resolve())
          .pipe(res);
      });
    } catch (e) { console.warn("storage check failed:", e.message); }
  }
  // 2) local fallback ../files/<file> (emulator / pre-Storage)
  const local = path.join(FILES_DIR, name);
  if (fs.existsSync(local)) return res.download(local);
  return res.status(404).json({ error: "File not on server. Upload Storage sock/" + name + " (or ../files/)" });
});

// seed helper: POST /api/admin/seed { key, expiry_date, max_devices } (protect with ADMIN_TOKEN env in prod)
app.post("/admin/seed", async (req, res) => {
  const need = process.env.ADMIN_TOKEN || "";
  if (need && req.headers["x-admin"] !== need) return res.status(403).json({ error: "forbidden" });
  const { key, expiry_date, max_devices } = req.body || {};
  if (!key) return res.status(400).json({ error: "key required" });
  const doc = { expiry_date: expiry_date || "2027-12-31", max_devices: max_devices || 1, hwid: null, active_devices: 0 };
  if (db) { try { await db.collection("licenses").doc(key).set(doc, { merge: true }); } catch (e) { return res.status(500).json({ error: e.message }); } }
  const all = loadLocalLicenses(); all[key] = doc; saveLocalLicenses(all);
  return res.json({ ok: true, key });
});

exports.api = onRequest({ region: "asia-south1", maxInstances: 10 }, app);

// local `node index.js` test hooks (NOT deployed)
module.exports._helpers = { xorCrypt, encryptData, decryptData, doAuth };
