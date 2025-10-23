// server.js (ESM) — Backend for GACE
// Required Environment Variables (set in Render or your host):
// ROOT_DOMAIN=gace.space
// CLOUDFLARE_ZONE_ID=xxxxxxxxxxxxxxxxxxxxxxxxxxxx
// CLOUDFLARE_API_TOKEN=cf_xxx_with_zone_dns_edit
// SESSION_SECRET=some-long-random-string
//
// Start: node server.js

import express from "express";
import session from "express-session";
import bodyParser from "body-parser";
import bcrypt from "bcryptjs";
import fs from "fs";
import path from "path";
import crypto from "crypto";
import { fileURLToPath } from "url";
import { promises as dns } from "node:dns";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// ====== ENV ======
const PORT = process.env.PORT || 3000;
const ROOT_DOMAIN = process.env.ROOT_DOMAIN || "gace.space";
const CLOUDFLARE_ZONE_ID = process.env.CLOUDFLARE_ZONE_ID || "";
const CLOUDFLARE_API_TOKEN = process.env.CLOUDFLARE_API_TOKEN || "";
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex");
const ADMIN_PINS = new Set(["2529", "2520"]);

if (!CLOUDFLARE_ZONE_ID || !CLOUDFLARE_API_TOKEN) {
  console.warn(
    "[WARN] CLOUDFLARE_ZONE_ID or CLOUDFLARE_API_TOKEN is missing. DNS operations will fail."
  );
}

// ====== MIDDLEWARE ======
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(
  session({
    name: "gace",
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      maxAge: 1000 * 60 * 60 * 8, // 8 hours
    },
  })
);

// Serve static files (index.html, dashboard.html live in repo root)
app.use(express.static(__dirname, { extensions: ["html"] }));

// ====== SIMPLE JSON "DB" ======
const USERS_FILE = path.join(__dirname, "users.json");
if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, JSON.stringify({ users: [] }, null, 2));

function readDB() {
  try {
    return JSON.parse(fs.readFileSync(USERS_FILE, "utf-8"));
  } catch {
    return { users: [] };
  }
}
function writeDB(db) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(db, null, 2));
}

// ====== UTILS ======
function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ ok: false, error: "unauthorized" });
  const db = readDB();
  const user = db.users.find((u) => u.id === req.session.userId);
  if (!user) return res.status(401).json({ ok: false, error: "unauthorized" });
  req.user = user;
  next();
}

function toFqdn(name) {
  const q = (name || "").trim().toLowerCase();
  if (!q) return "";
  return q.endsWith("." + ROOT_DOMAIN) ? q : `${q}.${ROOT_DOMAIN}`;
}

const CF_API = "https://api.cloudflare.com/client/v4";

async function cfFetch(path, options = {}) {
  const resp = await fetch(`${CF_API}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${CLOUDFLARE_API_TOKEN}`,
      ...(options.headers || {}),
    },
  });
  let data;
  try {
    data = await resp.json();
  } catch {
    throw new Error(`Cloudflare returned non-JSON status ${resp.status}`);
  }
  if (!resp.ok || data.success === false) {
    const msg = data?.errors?.[0]?.message || resp.statusText;
    throw new Error(`Cloudflare API error: ${msg}`);
  }
  return data;
}

async function cfListDNS({ name, type } = {}) {
  const params = new URLSearchParams({ per_page: "200" });
  if (name) params.set("name", name);
  if (type) params.set("type", type);
  const data = await cfFetch(`/zones/${CLOUDFLARE_ZONE_ID}/dns_records?${params.toString()}`, {
    method: "GET",
  });
  return data.result || [];
}

async function cfCreateDNS({ type, name, content, ttl = 300, proxied = false }) {
  const data = await cfFetch(`/zones/${CLOUDFLARE_ZONE_ID}/dns_records`, {
    method: "POST",
    body: JSON.stringify({ type, name, content, ttl, proxied }),
  });
  return data.result;
}

async function cfDeleteDNS(id) {
  const data = await cfFetch(`/zones/${CLOUDFLARE_ZONE_ID}/dns_records/${id}`, { method: "DELETE" });
  return data.result;
}

// ====== ROUTES (PAGES) ======
app.get("/", (_req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.get("/dashboard", (req, res) => {
  if (!req.session.userId) return res.redirect("/"); // require session
  res.sendFile(path.join(__dirname, "dashboard.html"));
});

// ====== AUTH ======
app.get("/api/me", (req, res) => {
  const db = readDB();
  const user = db.users.find((u) => u.id === req.session.userId);
  res.json({ ok: true, user: user ? { id: user.id, email: user.email } : null });
});

app.post("/api/signup", async (req, res) => {
  try {
    const { email, password, adminPin } = req.body || {};
    if (!email || !password || !adminPin) {
      return res.status(400).json({ ok: false, error: "missing_fields" });
    }
    if (!ADMIN_PINS.has(String(adminPin))) {
      return res.status(403).json({ ok: false, error: "invalid_pin" });
    }
    const db = readDB();
    const exists = db.users.find((u) => u.email.toLowerCase() === String(email).toLowerCase());
    if (exists) return res.status(409).json({ ok: false, error: "email_exists" });

    const passHash = await bcrypt.hash(password, 10);
    const user = {
      id: crypto.randomUUID(),
      email,
      passHash,
      createdAt: Date.now(),
    };
    db.users.push(user);
    writeDB(db);

    req.session.userId = user.id;
    res.json({ ok: true, user: { id: user.id, email: user.email } });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const db = readDB();
    const user = db.users.find((u) => u.email.toLowerCase() === String(email).toLowerCase());
    if (!user) return res.status(401).json({ ok: false, error: "invalid_creds" });
    const ok = await bcrypt.compare(password, user.passHash);
    if (!ok) return res.status(401).json({ ok: false, error: "invalid_creds" });
    req.session.userId = user.id;
    res.json({ ok: true, user: { id: user.id, email: user.email } });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({ ok: true });
  });
});

// ====== DNS ======

/**
 * Availability + live DNS resolve (no auth required).
 * GET /api/dns/check?name=sub or fqdn
 */
app.get("/api/dns/check", async (req, res) => {
  try {
    const qRaw = (req.query.name || "").trim();
    if (!qRaw) return res.status(400).json({ ok: false, error: "missing_name" });
    const fqdn = toFqdn(qRaw);

    let cfRecords = [];
    if (CLOUDFLARE_ZONE_ID && CLOUDFLARE_API_TOKEN) {
      try {
        cfRecords = await cfListDNS({ name: fqdn });
      } catch {}
    }

    const live = { A: [], CNAME: [], TXT: [] };
    try {
      live.A = await dns.resolve4(fqdn);
    } catch {}
    try {
      live.CNAME = await dns.resolveCname(fqdn);
    } catch {}
    try {
      live.TXT = await dns.resolveTxt(fqdn);
    } catch {}

    const available = (cfRecords.length === 0) && live.A.length === 0 && live.CNAME.length === 0;
    res.json({ ok: true, name: fqdn, available, cloudflareRecords: cfRecords, live });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

/**
 * List CF records (auth required).
 * GET /api/dns/list?name=&type=
 */
app.get("/api/dns/list", requireAuth, async (req, res) => {
  try {
    if (!CLOUDFLARE_ZONE_ID || !CLOUDFLARE_API_TOKEN) {
      return res.json({ ok: true, records: [], note: "Cloudflare env not set" });
    }
    const { name, type } = req.query;
    const fqdn = name ? toFqdn(name) : undefined;
    const records = await cfListDNS({ name: fqdn, type });
    res.json({ ok: true, records });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

/**
 * Create record (auth required).
 * POST /api/dns/create  { type, name, content, ttl, proxied }
 */
app.post("/api/dns/create", requireAuth, async (req, res) => {
  try {
    if (!CLOUDFLARE_ZONE_ID || !CLOUDFLARE_API_TOKEN) {
      return res.status(500).json({ ok: false, error: "cloudflare_env_missing" });
    }
    let { type, name, content, ttl = 300, proxied = false } = req.body || {};
    type = String(type || "").toUpperCase();
    if (!type || !name || !content) return res.status(400).json({ ok: false, error: "missing_fields" });
    if (!["A", "CNAME", "TXT"].includes(type)) {
      return res.status(400).json({ ok: false, error: "unsupported_type" });
    }
    const fqdn = toFqdn(name);

    // Avoid exact duplicates
    const existing = await cfListDNS({ name: fqdn, type });
    const dup = existing.find((r) => String(r.content).trim() === String(content).trim());
    if (dup) return res.status(409).json({ ok: false, error: "record_exists", record: dup });

    const created = await cfCreateDNS({
      type,
      name: fqdn,
      content: String(content).trim(),
      ttl: Number(ttl) || 300,
      proxied: Boolean(proxied),
    });
    res.json({ ok: true, record: created });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

/**
 * Delete record (auth required)
 * DELETE /api/dns/:id
 */
app.delete("/api/dns/:id", requireAuth, async (req, res) => {
  try {
    if (!CLOUDFLARE_ZONE_ID || !CLOUDFLARE_API_TOKEN) {
      return res.status(500).json({ ok: false, error: "cloudflare_env_missing" });
    }
    const result = await cfDeleteDNS(req.params.id);
    res.json({ ok: true, result });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ====== HEALTH ======
app.get("/healthz", (_req, res) => res.json({ ok: true, root: ROOT_DOMAIN }));

// ====== BOOT ======
app.listen(PORT, () => {
  console.log(`✅ GACE server running on http://localhost:${PORT}`);
  console.log(`   Root domain: ${ROOT_DOMAIN}`);
});
