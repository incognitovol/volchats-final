// server.js — VolChats (accounts + email verification + sessions + moderation + admin + maintenance + queue caps)
const path = require("path");
const express = require("express");
const http = require("http");
const WebSocket = require("ws");
const crypto = require("crypto");

const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
const nodemailer = require("nodemailer");

const app = express();
app.use(express.json({ limit: "2mb" }));
app.use(cookieParser());

const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

/* ---------------------------
   ENV
----------------------------*/
const PORT = process.env.PORT || 3000;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || "";
const JWT_SECRET = process.env.JWT_SECRET || "dev-change-me-now";
const COOKIE_NAME = "volchats_session";

// SMTP (optional). If not set, codes will be printed to terminal for dev testing.
const SMTP_SERVICE = process.env.SMTP_SERVICE || ""; // for Gmail: "gmail"
const SMTP_HOST = process.env.SMTP_HOST || "";
const SMTP_PORT = Number(process.env.SMTP_PORT || 0);
const SMTP_USER = process.env.SMTP_USER || "";
const SMTP_PASS = process.env.SMTP_PASS || "";
const SMTP_FROM = process.env.SMTP_FROM || "VolChats <no-reply@volchats.local>";

const IS_PROD = process.env.NODE_ENV === "production";

// Maintenance + Capacity caps (queue)
const MAINTENANCE_MODE =
  String(process.env.MAINTENANCE_MODE || process.env.MAINTENANCE || "").trim() === "1";
const MAINTENANCE_MESSAGE = String(process.env.MAINTENANCE_MESSAGE || "").trim();

// Room caps (NOT users). 20 rooms = 40 users in video. 80 rooms = 160 users in text.
const MAX_VIDEO_ROOMS = Math.max(1, Number(process.env.MAX_VIDEO_ROOMS || 20));
const MAX_TEXT_ROOMS = Math.max(1, Number(process.env.MAX_TEXT_ROOMS || 80));

/* ---------------------------
   Maintenance gate (admin still works)
----------------------------*/
app.use((req, res, next) => {
  if (!MAINTENANCE_MODE) return next();

  const p = req.path || "/";

  // allow admin + admin apis + maintenance page
  if (p === "/maintenance.html" || p === "/admin.html" || p.startsWith("/admin")) return next();

  // allow non-html assets to still load (css/js/img)
  if (req.method === "GET" && !p.endsWith(".html") && !p.startsWith("/api/")) return next();

  // block user-facing APIs during maintenance
  if (p.startsWith("/api/")) {
    return res.status(503).json({
      error: "Maintenance",
      message: MAINTENANCE_MESSAGE || "VolChats is down for maintenance. Try again soon.",
    });
  }

  // everything else -> maintenance page
  return res.sendFile(path.join(__dirname, "maintenance.html"));
});

// Protect admin.html before static middleware
app.get("/admin.html", adminGuard, (req, res) => {
  res.sendFile(path.join(__dirname, "admin.html"));
});

// static after maintenance gate
app.use(express.static(path.join(__dirname, ".")));

/* ---------------------------
   DB (SQLite)
----------------------------*/
const dbPath = process.env.DB_PATH || path.join(__dirname, "volchats.db");
const db = new Database(dbPath);
db.pragma("journal_mode = WAL");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL UNIQUE,
  username TEXT NOT NULL UNIQUE,
  gender TEXT NOT NULL,
  class_year TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL,
  last_login_at TEXT
);

CREATE TABLE IF NOT EXISTS email_codes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL,
  code_hash TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_email_codes_email ON email_codes(email);

CREATE TABLE IF NOT EXISTS bans (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  email TEXT,
  ip TEXT,
  reason TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_bans_user_id ON bans(user_id);
CREATE INDEX IF NOT EXISTS idx_bans_email ON bans(email);
CREATE INDEX IF NOT EXISTS idx_bans_ip ON bans(ip);
`);

/* ---------------------------
   Helpers
----------------------------*/
function nowIso() {
  return new Date().toISOString();
}
function addMinutesIso(min) {
  return new Date(Date.now() + min * 60 * 1000).toISOString();
}
function sha256(str) {
  return crypto.createHash("sha256").update(String(str)).digest("hex");
}
function random6() {
  return String(Math.floor(100000 + Math.random() * 900000));
}
function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}
function isValidUtkEmail(email) {
  // STRICT: UTK student email must be @vols.utk.edu
  return /^[a-z0-9._%+-]+@vols\.utk\.edu$/i.test(email);
}
function normalizeUsername(u) {
  return String(u || "").trim();
}
function isValidUsername(u) {
  // 3-20 chars, letters numbers underscore dot
  return /^[a-zA-Z0-9._]{3,20}$/.test(u);
}
function getIp(reqOrWs) {
  if (reqOrWs && reqOrWs.headers) {
    return (
      reqOrWs.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
      reqOrWs.socket?.remoteAddress ||
      "unknown"
    );
  }
  return reqOrWs?._socket?.remoteAddress || "unknown";
}

// stable key for "never match again"
function pairKey(a, b) {
  const x = String(a);
  const y = String(b);
  return x < y ? `${x}::${y}` : `${y}::${x}`;
}

function setSessionCookie(res, payload) {
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: "30d" });
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    sameSite: "lax",
    secure: IS_PROD,
    maxAge: 30 * 24 * 60 * 60 * 1000,
  });
}

function clearSessionCookie(res) {
  res.clearCookie(COOKIE_NAME, {
    httpOnly: true,
    sameSite: "lax",
    secure: IS_PROD,
  });
}

function getSession(req) {
  const token = req.cookies[COOKIE_NAME];
  if (!token) return null;
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch {
    return null;
  }
}

function authRequired(req, res, next) {
  const s = getSession(req);
  if (!s?.userId) return res.status(401).json({ error: "Not logged in" });
  req.userSession = s;
  next();
}

/* ---------------------------
   Admin guard
----------------------------*/
function isLocalhost(req) {
  const ip = req.ip || req.connection?.remoteAddress || "";
  return ip.includes("127.0.0.1") || ip.includes("::1") || ip.includes("::ffff:127.0.0.1");
}

function adminGuard(req, res, next) {
  if (ADMIN_TOKEN) {
    const header = req.headers.authorization || "";
    const bearer = header.startsWith("Bearer ") ? header.slice(7).trim() : "";
    const token = bearer || (req.query.token ? String(req.query.token) : "");
    if (token !== ADMIN_TOKEN) return res.status(401).json({ error: "Unauthorized" });
    return next();
  }
  if (!isLocalhost(req)) return res.status(401).json({ error: "Unauthorized (localhost only)" });
  next();
}

/* ---------------------------
   Email sender (SMTP optional)
----------------------------*/
let transporter = null;

// Support BOTH modes:
// 1) Gmail mode: SMTP_SERVICE="gmail" + SMTP_USER + SMTP_PASS (Google App Password)
// 2) Host/port mode (Brevo/etc): SMTP_HOST + SMTP_PORT + SMTP_USER + SMTP_PASS
try {
  if (SMTP_USER && SMTP_PASS) {
    if (SMTP_SERVICE) {
      transporter = nodemailer.createTransport({
        service: SMTP_SERVICE,
        auth: { user: SMTP_USER, pass: SMTP_PASS },
      });
    } else if (SMTP_HOST && SMTP_PORT) {
      transporter = nodemailer.createTransport({
        host: SMTP_HOST,
        port: SMTP_PORT,
        secure: SMTP_PORT === 465,
        auth: { user: SMTP_USER, pass: SMTP_PASS },
      });
    }
  }
} catch (e) {
  console.log("[VolChats] SMTP init failed:", e?.message || e);
  transporter = null;
}

async function sendVerificationEmail(email, code) {
   // If SMTP not configured, just print the code
  if (!transporter) {
    console.log("\n[VolChats] EMAIL VERIFICATION CODE (DEV MODE):");
    console.log("Email:", email);
    console.log("Code :", code);
    console.log("------------------------------------------------\n");
    return;
  }

try {
  await transporter.sendMail({
    from: SMTP_FROM,
    to: email,
    subject: "Your VolChats verification code",
    text: `Your VolChats verification code is: ${code}\n\nThis code expires in 10 minutes.`,
  });
} catch (err) {
   console.log("\n[VolChats] SMTP SEND FAILED - falling back to DEV MODE");
   console.log("Error:", err?.message || err);
   console.log("Email:", email);
   console.log("Code :", code);
   console.log("------------------------------------------------\n");

   //Do Not crash the server
   return;
 }
}

/* ---------------------------
   Ban check
----------------------------*/
function getActiveBanByEmailOrIp(email, ip, userId) {
  const now = nowIso();
  const ban =
    db
      .prepare(
        `
    SELECT * FROM bans
    WHERE active=1
      AND expires_at > ?
      AND (
        (user_id IS NOT NULL AND user_id = ?)
        OR (email IS NOT NULL AND email = ?)
        OR (ip IS NOT NULL AND ip = ?)
      )
    ORDER BY id DESC
    LIMIT 1
    `
      )
      .get(now, userId || -1, email || "", ip || "") || null;

  return ban;
}

/* ---------------------------
   Protect chat pages: must be logged in
----------------------------*/
app.get(["/video.html", "/text.html"], (req, res, next) => {
  if (MAINTENANCE_MODE) {
    return res.redirect(
      `/maintenance.html${MAINTENANCE_MESSAGE ? `?msg=${encodeURIComponent(MAINTENANCE_MESSAGE)}` : ""}`
    );
  }

  const sess = getSession(req);
  if (!sess?.userId) {
    return res.redirect("/auth.html");
  }

  const ip = getIp(req);
  const ban = getActiveBanByEmailOrIp(sess.email, ip, sess.userId);
  if (ban) {
    clearSessionCookie(res);
    return res.redirect(
      `/auth.html?banned=1&until=${encodeURIComponent(ban.expires_at)}&reason=${encodeURIComponent(ban.reason)}`
    );
  }

  next();
});

/* ---------------------------
   AUTH API
----------------------------*/

// Request a code
app.post("/api/auth/request-code", async (req, res) => {
  const email = normalizeEmail(req.body.email);
  if (!isValidUtkEmail(email)) return res.status(400).json({ error: "Must use a valid @vols.utk.edu email" });

  db.prepare("UPDATE email_codes SET used=1 WHERE email=?").run(email);

  const code = random6();
  const codeHash = sha256(code);
  const createdAt = nowIso();
  const expiresAt = addMinutesIso(10);

  db.prepare(
    "INSERT INTO email_codes (email, code_hash, created_at, expires_at, used) VALUES (?,?,?,?,0)"
  ).run(email, codeHash, createdAt, expiresAt);

  const sent = await sendVerificationEmail(email, code);

  res.json({ ok: true, sent });
});

// Verify code
app.post("/api/auth/verify-code", (req, res) => {
  const email = normalizeEmail(req.body.email);
  const code = String(req.body.code || "").trim();

  if (!isValidUtkEmail(email)) return res.status(400).json({ error: "Invalid email" });
  if (!/^\d{6}$/.test(code)) return res.status(400).json({ error: "Invalid code" });

  const row = db
    .prepare(
      `
    SELECT * FROM email_codes
    WHERE email=? AND used=0
    ORDER BY id DESC
    LIMIT 1
  `
    )
    .get(email);

  if (!row) return res.status(400).json({ error: "No active code. Request a new one." });
  if (new Date(row.expires_at).getTime() < Date.now()) return res.status(400).json({ error: "Code expired. Request a new one." });

  const ok = sha256(code) === row.code_hash;
  if (!ok) return res.status(400).json({ error: "Wrong code" });

  res.json({ ok: true });
});

// Register
app.post("/api/auth/register", (req, res) => {
  const email = normalizeEmail(req.body.email);
  const code = String(req.body.code || "").trim();
  const username = normalizeUsername(req.body.username);
  const gender = String(req.body.gender || "").trim().toLowerCase();
  const classYear = String(req.body.classYear || "").trim().toLowerCase();
  const password = String(req.body.password || "");

  if (!isValidUtkEmail(email)) return res.status(400).json({ error: "Must use a valid @vols.utk.edu email" });
  if (!/^\d{6}$/.test(code)) return res.status(400).json({ error: "Invalid code" });
  if (!isValidUsername(username)) return res.status(400).json({ error: "Username must be 3-20 chars: letters/numbers/._" });
  if (!(gender === "male" || gender === "female")) return res.status(400).json({ error: "Gender must be male or female" });

  const validYears = new Set(["freshman", "sophomore", "junior", "senior"]);
  if (!validYears.has(classYear)) return res.status(400).json({ error: "Class year must be freshman/sophomore/junior/senior" });

  if (password.length < 8) return res.status(400).json({ error: "Password must be at least 8 characters" });

  const row = db
    .prepare(
      `
    SELECT * FROM email_codes
    WHERE email=? AND used=0
    ORDER BY id DESC
    LIMIT 1
  `
    )
    .get(email);

  if (!row) return res.status(400).json({ error: "No active code. Request a new one." });
  if (new Date(row.expires_at).getTime() < Date.now()) return res.status(400).json({ error: "Code expired. Request a new one." });
  if (sha256(code) !== row.code_hash) return res.status(400).json({ error: "Wrong code" });

  const existingEmail = db.prepare("SELECT id FROM users WHERE email=?").get(email);
  if (existingEmail) return res.status(400).json({ error: "Email already has an account. Login instead." });

  const existingUser = db.prepare("SELECT id FROM users WHERE username=?").get(username);
  if (existingUser) return res.status(400).json({ error: "Username already taken." });

  const passwordHash = bcrypt.hashSync(password, 12);

  const createdAt = nowIso();
  const info = db
    .prepare(
      "INSERT INTO users (email, username, gender, class_year, password_hash, created_at) VALUES (?,?,?,?,?,?)"
    )
    .run(email, username, gender, classYear, passwordHash, createdAt);

  db.prepare("UPDATE email_codes SET used=1 WHERE id=?").run(row.id);

  const userId = info.lastInsertRowid;

  setSessionCookie(res, { userId, email, username });

  res.json({ ok: true, user: { userId, email, username, gender, classYear } });
});

// Login (email OR username)
app.post("/api/auth/login", (req, res) => {
  const login = String(req.body.login || "").trim();
  const password = String(req.body.password || "");

  if (!login || !password) return res.status(400).json({ error: "Missing login/password" });

  const emailMaybe = normalizeEmail(login);

  const user =
    (isValidUtkEmail(emailMaybe)
      ? db.prepare("SELECT * FROM users WHERE email=?").get(emailMaybe)
      : db.prepare("SELECT * FROM users WHERE username=?").get(login)) || null;

  if (!user) return res.status(400).json({ error: "Invalid credentials" });

  const ok = bcrypt.compareSync(password, user.password_hash);
  if (!ok) return res.status(400).json({ error: "Invalid credentials" });

  const ip = getIp(req);
  const ban = getActiveBanByEmailOrIp(user.email, ip, user.id);
  if (ban) {
    return res.status(403).json({ error: "Banned", reason: ban.reason, until: ban.expires_at });
  }

  db.prepare("UPDATE users SET last_login_at=? WHERE id=?").run(nowIso(), user.id);

  setSessionCookie(res, { userId: user.id, email: user.email, username: user.username });
  res.json({ ok: true, user: { userId: user.id, email: user.email, username: user.username } });
});

app.post("/api/auth/logout", (req, res) => {
  clearSessionCookie(res);
  res.json({ ok: true });
});

app.get("/api/me", authRequired, (req, res) => {
  const u = db.prepare("SELECT id, email, username, gender, class_year, created_at, last_login_at FROM users WHERE id=?")
    .get(req.userSession.userId);

  if (!u) {
    clearSessionCookie(res);
    return res.status(401).json({ error: "Not logged in" });
  }

  res.json({ ok: true, user: u });
});

/* ---------------------------
   Admin: list users
----------------------------*/
app.get("/admin/users", adminGuard, (req, res) => {
  const limit = Math.max(1, Math.min(Number(req.query.limit || 200), 1000));
  const rows = db
    .prepare("SELECT id, email, username, gender, class_year, created_at, last_login_at FROM users ORDER BY id DESC LIMIT ?")
    .all(limit);
  res.json({ count: rows.length, users: rows });
});

/* ---------------------------
   Moderation / Reports (Admin)
----------------------------*/
function makeReportId() {
  return "rep_" + crypto.randomBytes(8).toString("hex") + "_" + Date.now().toString(36);
}

const reports = []; // oldest -> newest
const reportsById = new Map();
const reportCountByUserId = new Map(); // userId -> count
const reportCountByEmail = new Map(); // email -> count
const reportCountByIp = new Map(); // ip -> count

function getReports(limit = 200) {
  const slice = reports.slice(Math.max(0, reports.length - limit));
  return slice.reverse(); // newest first
}

app.get("/admin/reports", adminGuard, (req, res) => {
  const limit = Math.max(1, Math.min(Number(req.query.limit || 200), 1000));
  res.json({ count: Math.min(limit, reports.length), reports: getReports(limit) });
});

app.get("/admin/reports/:id", adminGuard, (req, res) => {
  const r = reportsById.get(req.params.id) || null;
  if (!r) return res.status(404).json({ error: "Not found" });
  res.json(r);
});

app.post("/admin/reports/:id/clear", adminGuard, (req, res) => {
  const r = reportsById.get(req.params.id) || null;
  if (!r) return res.status(404).json({ error: "Not found" });

  r.status = "cleared";

  const ip = r?.reported?.ip || "";
  const email = r?.reported?.email || "";
  const userId = r?.reported?.userId || null;

  if (ip) db.prepare("UPDATE bans SET active=0 WHERE ip=? AND active=1").run(ip);
  if (email) db.prepare("UPDATE bans SET active=0 WHERE email=? AND active=1").run(email);
  if (userId) db.prepare("UPDATE bans SET active=0 WHERE user_id=? AND active=1").run(userId);

  res.json({ ok: true });
});

// Ban: supports account-based bans (userId + email) PLUS ip for backup.
app.post("/admin/ban", adminGuard, (req, res) => {
  const ip = String(req.body.ip || "").trim();
  const email = normalizeEmail(req.body.email || "");
  const userIdRaw = req.body.userId;
  const userId = userIdRaw === null || userIdRaw === undefined || userIdRaw === "" ? null : Number(userIdRaw);

  const durationMinutes = Math.max(1, Number(req.body.durationMinutes || 0));
  const reason = String(req.body.reason || "Inappropriate behavior").trim();
  const reportId = String(req.body.reportId || "").trim();

  if (!Number.isFinite(durationMinutes) || durationMinutes <= 0) {
    return res.status(400).json({ error: "Invalid durationMinutes" });
  }

  // require at least one identifier
  if (!ip && !email && !(Number.isFinite(userId) && userId > 0)) {
    return res.status(400).json({ error: "Missing identifiers (need ip and/or email and/or userId)" });
  }

  const createdAt = nowIso();
  const expiresAt = addMinutesIso(durationMinutes);

  db.prepare(
    "INSERT INTO bans (user_id, email, ip, reason, created_at, expires_at, active) VALUES (?,?,?,?,?,?,1)"
  ).run(
    Number.isFinite(userId) && userId > 0 ? userId : null,
    email || null,
    ip || null,
    reason,
    createdAt,
    expiresAt
  );

  if (reportId) {
    const r = reportsById.get(reportId);
    if (r) r.status = "banned";
  }

  res.json({ ok: true, userId: userId || null, email: email || null, ip: ip || null, expiresAt, reason });
});

/* ---------------------------
   WebSocket matchmaking + chat + report + QUEUE CAPS
----------------------------*/
function safeWsSend(ws, obj) {
  if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(obj));
}
function makeWsId(prefix = "sock") {
  return `${prefix}_${Math.random().toString(36).slice(2)}_${Date.now().toString(36)}`;
}

const clients = new Set();
const waitingVideo = [];
const waitingText = [];
const hardBlocks = new Set();

function broadcastUserCount() {
  const payload = JSON.stringify({ type: "user-count", count: clients.size });
  for (const c of clients) {
    if (c.readyState === WebSocket.OPEN) c.send(payload);
  }
}

function queueFor(ws) {
  return ws.mode === "text" ? waitingText : waitingVideo;
}
function cleanQueue(queue) {
  for (let i = 0; i < queue.length; i++) {
    const c = queue[i];
    if (!c || c.readyState !== WebSocket.OPEN || c.partner) {
      queue.splice(i, 1);
      i--;
    }
  }
}
function markLastPartners(a, b) {
  if (a) a.lastPartnerId = b ? b.id : null;
  if (b) b.lastPartnerId = a ? a.id : null;
}
function canMatch(a, b) {
  if (!a || !b) return false;
  if (hardBlocks.has(pairKey(a.id, b.id))) return false;
  if (clients.size <= 2) return true;
  if (a.lastPartnerId && a.lastPartnerId === b.id) return false;
  if (b.lastPartnerId && b.lastPartnerId === a.id) return false;
  return true;
}
function pairUsers(a, b) {
  a.partner = b;
  b.partner = a;
  safeWsSend(a, { type: "matched", initiator: true, self: a.profile || null, partner: b.profile || null });
  safeWsSend(b, { type: "matched", initiator: false, self: b.profile || null, partner: a.profile || null });
}
function unpairMutual(a, b) {
  if (a && a.partner === b) a.partner = null;
  if (b && b.partner === a) b.partner = null;
}

// QUEUE + CAP HELPERS
function roomLimitFor(mode) {
  return mode === "text" ? MAX_TEXT_ROOMS : MAX_VIDEO_ROOMS;
}

// counts active rooms (pairs) per mode (counts each pair once)
function countActiveRooms(mode) {
  let rooms = 0;
  for (const c of clients) {
    if (!c || c.readyState !== WebSocket.OPEN) continue;
    if (c.mode !== mode) continue;
    if (!c.partner) continue;

    const a = String(c.id || "");
    const b = String(c.partner?.id || "");
    if (a && b && a < b) rooms++;
  }
  return rooms;
}

// ✅ Sends queue payload with BOTH naming styles so any front-end works
function sendQueueUpdate(ws) {
  if (!ws || ws.readyState !== WebSocket.OPEN || !ws.mode || ws.partner) return;
  const q = queueFor(ws);
  cleanQueue(q);
  const pos = q.indexOf(ws);
  if (pos >= 0) {
    const active = countActiveRooms(ws.mode);
    const max = roomLimitFor(ws.mode);

    safeWsSend(ws, {
      type: "queue",
      mode: ws.mode,

      // legacy keys (your server)
      position: pos + 1,
      waiting: q.length,
      activeRooms: active,
      maxRooms: max,

      // ✅ new keys (what your new UI expects)
      total: q.length,
      roomsActive: active,
      roomsMax: max,
    });
  }
}

function broadcastQueueUpdates(mode) {
  const q = mode === "text" ? waitingText : waitingVideo;
  cleanQueue(q);

  const active = countActiveRooms(mode);
  const max = roomLimitFor(mode);

  for (let i = 0; i < q.length; i++) {
    const ws = q[i];
    safeWsSend(ws, {
      type: "queue",
      mode,

      // legacy keys
      position: i + 1,
      waiting: q.length,
      activeRooms: active,
      maxRooms: max,

      // ✅ new keys
      total: q.length,
      roomsActive: active,
      roomsMax: max,
    });
  }
}

// ✅ NEW: drain queue when room frees up, so users actually get pulled in automatically
function drainQueue(mode) {
  const limit = roomLimitFor(mode);
  const q = mode === "text" ? waitingText : waitingVideo;
  cleanQueue(q);

  // while capacity and at least 2 waiting users, try to pair them
  while (countActiveRooms(mode) < limit && q.length >= 2) {
    const a = q[0];
    if (!a || a.readyState !== WebSocket.OPEN || a.partner) {
      q.shift();
      continue;
    }

    let matched = false;
    for (let i = 1; i < q.length; i++) {
      const b = q[i];
      if (!b || b.readyState !== WebSocket.OPEN || b.partner) continue;

      if (canMatch(a, b)) {
        // remove b first, then a
        q.splice(i, 1);
        q.splice(0, 1);
        pairUsers(a, b);
        matched = true;
        break;
      }
    }

    // if a couldn't find partner, stop draining (avoid infinite loops)
    if (!matched) break;
  }

  broadcastQueueUpdates(mode);
}

function tryMatch(ws) {
  if (!ws || ws.readyState !== WebSocket.OPEN) return;
  if (!ws.mode) return;
  if (ws.partner) return;

  const mode = ws.mode;
  const limit = roomLimitFor(mode);
  const queue = queueFor(ws);

  cleanQueue(queue);

  // If we are at capacity, put user in queue and tell them position
  if (countActiveRooms(mode) >= limit) {
    if (!queue.includes(ws)) queue.push(ws);
    sendQueueUpdate(ws);
    broadcastQueueUpdates(mode);
    return;
  }

  // Try to find a partner
  for (let i = 0; i < queue.length; i++) {
    const candidate = queue[i];
    if (!candidate || candidate === ws) continue;
    if (candidate.readyState !== WebSocket.OPEN || candidate.partner) continue;

    // capacity check again right before pairing
    if (countActiveRooms(mode) >= limit) {
      if (!queue.includes(ws)) queue.push(ws);
      sendQueueUpdate(ws);
      broadcastQueueUpdates(mode);
      return;
    }

    if (canMatch(ws, candidate)) {
      queue.splice(i, 1); // remove candidate
      // ws might already be in queue; remove it too
      const j = queue.indexOf(ws);
      if (j >= 0) queue.splice(j, 1);

      pairUsers(candidate, ws);

      // after pairing, try pulling more pairs if capacity allows
      drainQueue(mode);
      return;
    }
  }

  // No match found yet -> wait in queue
  if (!queue.includes(ws)) queue.push(ws);
  sendQueueUpdate(ws);
  broadcastQueueUpdates(mode);
}

function pushMsgHistory(ws, fromId, text) {
  if (!ws) return;
  if (!ws.lastMessages) ws.lastMessages = [];
  ws.lastMessages.push({ ts: nowIso(), fromId: String(fromId || ""), text: String(text || "") });
  if (ws.lastMessages.length > 30) ws.lastMessages.shift();
}

function bumpCount(map, key) {
  if (!key) return 0;
  const prev = map.get(key) || 0;
  const next = prev + 1;
  map.set(key, next);
  return next;
}

function createReport({ reporter, reported, screenshotDataUrl = "" }) {
  const reportId = makeReportId();
  const createdAt = nowIso();

  const reportedIp = getIp(reported) || "unknown";
  const reporterIp = getIp(reporter) || "unknown";

  const reportedProfile = reported?.profile || null;
  const reporterProfile = reporter?.profile || null;

  const countIp = bumpCount(reportCountByIp, reportedIp);
  const countEmail = bumpCount(reportCountByEmail, reportedProfile?.email || "");
  const countUserId = bumpCount(reportCountByUserId, reportedProfile?.userId || "");

  const lastA = Array.isArray(reporter.lastMessages) ? reporter.lastMessages : [];
  const lastB = Array.isArray(reported.lastMessages) ? reported.lastMessages : [];
  const merged = [...lastA, ...lastB]
    .sort((x, y) => new Date(x.ts).getTime() - new Date(y.ts).getTime())
    .slice(-30);

  const rep = {
    reportId,
    createdAt,
    status: "open",
    reporter: {
      ip: reporterIp,
      userId: reporterProfile?.userId || null,
      email: reporterProfile?.email || null,
      username: reporterProfile?.username || null,
    },
    reported: {
      ip: reportedIp,
      socketId: reported.id || "",
      userId: reportedProfile?.userId || null,
      email: reportedProfile?.email || null,
      username: reportedProfile?.username || null,
      gender: reportedProfile?.gender || null,
      classYear: reportedProfile?.classYear || null,
      totalReportsOnThisIp: countIp,
      totalReportsOnThisEmail: reportedProfile?.email ? countEmail : null,
      totalReportsOnThisUserId: reportedProfile?.userId ? countUserId : null,
    },
    evidence: { screenshotDataUrl: screenshotDataUrl || "", lastMessages: merged },
  };

  reports.push(rep);
  reportsById.set(reportId, rep);

  if (reports.length > 500) {
    const old = reports.shift();
    if (old?.reportId) reportsById.delete(old.reportId);
  }

  return rep;
}

wss.on("connection", (ws, req) => {
  // hard block WebSockets during maintenance
  if (MAINTENANCE_MODE) {
    safeWsSend(ws, { type: "maintenance" });
    try { ws.close(); } catch {}
    return;
  }

  clients.add(ws);

  ws.id = makeWsId();
  ws.mode = null;
  ws.partner = null;
  ws.lastPartnerId = null;
  ws.lastMessages = [];
  ws.profile = null;

  broadcastUserCount();

  // attach logged-in profile to socket (so admin sees username/email on report)
  try {
    const cookieHeader = req?.headers?.cookie || "";
    const cookies = Object.fromEntries(
      cookieHeader
        .split(";")
        .map((p) => p.trim())
        .filter(Boolean)
        .map((p) => {
          const i = p.indexOf("=");
          return [decodeURIComponent(p.slice(0, i)), decodeURIComponent(p.slice(i + 1))];
        })
    );
    const token = cookies[COOKIE_NAME];
    if (token) {
      const sess = jwt.verify(token, JWT_SECRET);
      const u = db.prepare("SELECT id, email, username, gender, class_year FROM users WHERE id=?").get(sess.userId);
      if (u) {
        ws.profile = {
          userId: u.id,
          email: u.email,
          username: u.username,
          gender: u.gender,
          classYear: u.class_year,
        };
      }
    }
  } catch {}

  // If a banned user somehow gets here, force reset + close (extra safety)
  try {
    if (ws.profile?.userId) {
      const ban = getActiveBanByEmailOrIp(ws.profile.email, getIp(ws), ws.profile.userId);
      if (ban) {
        safeWsSend(ws, { type: "force-reset", reason: "banned" });
        try { ws.close(); } catch {}
        return;
      }
    }
  } catch {}

  ws.on("message", (raw) => {
    let data;
    try { data = JSON.parse(raw); } catch { return; }

    if (data.type === "join") {
      ws.mode = data.mode === "text" ? "text" : "video";
      tryMatch(ws);
      return;
    }

    if (data.type === "skip" || data.type === "leave") {
      const partner = ws.partner;

      if (partner && partner.readyState === WebSocket.OPEN) {
        markLastPartners(ws, partner);
        safeWsSend(partner, { type: "partner-left" });
        unpairMutual(ws, partner);
        tryMatch(partner);
      } else {
        ws.partner = null;
      }

      if (data.type === "skip") tryMatch(ws);

      // ✅ room freed -> drain queues
      drainQueue("video");
      drainQueue("text");
      return;
    }

    if (data.type === "offer" || data.type === "answer" || data.type === "ice") {
      const partner = ws.partner;
      if (partner && partner.readyState === WebSocket.OPEN) safeWsSend(partner, data);
      return;
    }

    if (data.type === "chat") {
      const msg = String(data.message || "");
      const partner = ws.partner;

      pushMsgHistory(ws, ws.id, msg);
      if (partner) pushMsgHistory(partner, ws.id, msg);

      if (partner && partner.readyState === WebSocket.OPEN) safeWsSend(partner, { type: "chat", message: msg });
      return;
    }

    if (data.type === "report") {
      const reporter = ws;
      const reported = ws.partner;

      if (!reported || reported.readyState !== WebSocket.OPEN) {
        safeWsSend(ws, { type: "force-reset", reason: "reporter" });
        ws.partner = null;
        tryMatch(ws);

        // ✅ room freed -> drain queues
        drainQueue("video");
        drainQueue("text");
        return;
      }

      // hard block: these two never match again
      hardBlocks.add(pairKey(reporter.id, reported.id));

      const screenshotDataUrl = String(data.screenshotDataUrl || "");
      createReport({ reporter, reported, screenshotDataUrl });

      markLastPartners(reporter, reported);
      unpairMutual(reporter, reported);

      safeWsSend(reporter, { type: "force-reset", reason: "reporter" });
      safeWsSend(reported, { type: "force-reset", reason: "reported" });

      tryMatch(reporter);
      tryMatch(reported);

      // ✅ room freed -> drain queues
      drainQueue("video");
      drainQueue("text");
      return;
    }
  });

  ws.on("close", () => {
    clients.delete(ws);

    const partner = ws.partner;
    if (partner && partner.readyState === WebSocket.OPEN && partner.partner === ws) {
      markLastPartners(partner, ws);
      safeWsSend(partner, { type: "partner-left" });
      partner.partner = null;
      tryMatch(partner);
    }

    broadcastUserCount();

    // ✅ room freed -> drain queues
    drainQueue("video");
    drainQueue("text");
  });
});

server.listen(PORT, () => {
  console.log("VolChats running on http://localhost:" + PORT);
  console.log("DB:", path.join(__dirname, "volchats.db"));
  if (ADMIN_TOKEN) console.log("ADMIN_TOKEN is set");
  else console.log("ADMIN_TOKEN not set (admin localhost-only)");

  console.log("Maintenance:", MAINTENANCE_MODE ? "ON" : "OFF");
  console.log("Caps:", { MAX_VIDEO_ROOMS, MAX_TEXT_ROOMS });

  // Better SMTP logging (works for both service and host mode)
  if (transporter) {
    if (SMTP_SERVICE) console.log("SMTP enabled via service:", SMTP_SERVICE);
    else console.log("SMTP enabled via host:", SMTP_HOST, "port:", SMTP_PORT);
  } else {
    console.log("SMTP not set: codes will print in terminal (dev mode)");
  }
});
