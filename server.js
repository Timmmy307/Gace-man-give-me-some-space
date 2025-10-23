/**
 * GACE • Educational Website Registrar
 * Single-file Node server (Express) + embedded index.html UI
 * Features:
 *  - Email/password auth with signup pin check (2529 or 2520)
 *  - Session cookies
 *  - Cloudflare DNS: list/create/delete A/CNAME/TXT records
 *  - Subdomain availability & live DNS resolution checks
 *
 * ENV required:
 *   PORT=8000
 *   ROOT_DOMAIN=gace.space              # your base zone (must exist in Cloudflare)
 *   CLOUDFLARE_ZONE_ID=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
 *   CLOUDFLARE_API_TOKEN=cf_api_token_with_zone_dns_edit
 *
 * References: Cloudflare DNS Records API (list/create/delete), Token permissions & Zone/Account IDs
 * https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/create/
 * https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/list/
 * https://developers.cloudflare.com/fundamentals/api/reference/permissions/
 * https://developers.cloudflare.com/fundamentals/account/find-account-and-zone-ids/
 */

import express from "express";
import path from "path";
import fs from "fs";
import crypto from "crypto";
import morgan from "morgan";
import bcrypt from "bcryptjs";
import cookieSession from "cookie-session";
import { fileURLToPath } from "url";
import { promises as dns } from "node:dns";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// ----- Config / Env -----
const PORT = process.env.PORT || 8000;
const ROOT_DOMAIN = process.env.ROOT_DOMAIN || "gace.space";
const CF_ZONE_ID = process.env.CLOUDFLARE_ZONE_ID || "";
const CF_API_TOKEN = process.env.CLOUDFLARE_API_TOKEN || "";

if (!CF_ZONE_ID || !CF_API_TOKEN) {
  console.warn(
    "\n[WARN] Cloudflare env not set. Set CLOUDFLARE_ZONE_ID and CLOUDFLARE_API_TOKEN to actually create DNS records.\n"
  );
}

// Allowed admin pins for signup
const ALLOWED_PINS = new Set(["2529", "2520"]);

// Very light file-backed store (single file) to persist users & records minimally.
const DATA_PATH = path.join(__dirname, "data.json");
function loadDB() {
  try {
    return JSON.parse(fs.readFileSync(DATA_PATH, "utf-8"));
  } catch {
    return { users: [], sessions: {} };
  }
}
function saveDB() {
  fs.writeFileSync(DATA_PATH, JSON.stringify(DB, null, 2));
}
const DB = loadDB();

// ----- Middleware -----
app.use(morgan("dev"));
app.use(express.json({ limit: "1mb" }));
app.use(
  cookieSession({
    name: "gace",
    // ephemeral key per boot; optional: replace with env SECRET for restarts
    keys: [process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex")],
    httpOnly: true,
    sameSite: "lax",
    maxAge: 1000 * 60 * 60 * 8, // 8h
  })
);

// Helper: require auth
function requireAuth(req, res, next) {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ ok: false, error: "unauthorized" });
  }
  const user = DB.users.find((u) => u.id === req.session.userId);
  if (!user) return res.status(401).json({ ok: false, error: "unauthorized" });
  req.user = user;
  next();
}

// ----- Cloudflare helper -----
const CF_API_BASE = "https://api.cloudflare.com/client/v4";

async function cfFetch(path, options = {}) {
  const resp = await fetch(`${CF_API_BASE}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${CF_API_TOKEN}`,
      ...(options.headers || {}),
    },
  });
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok || data.success === false) {
    const msg = data?.errors?.[0]?.message || resp.statusText;
    const code = data?.errors?.[0]?.code;
    throw new Error(`Cloudflare API error: ${msg}${code ? ` (${code})` : ""}`);
  }
  return data;
}

async function cfListDNS({ name, type } = {}) {
  const params = new URLSearchParams();
  if (name) params.set("name", name);
  if (type) params.set("type", type);
  params.set("per_page", "200");
  const data = await cfFetch(`/zones/${CF_ZONE_ID}/dns_records?` + params.toString(), {
    method: "GET",
  });
  return data.result || [];
}

async function cfCreateDNS({ type, name, content, ttl = 300, proxied = false }) {
  const body = { type, name, content, ttl, proxied };
  const data = await cfFetch(`/zones/${CF_ZONE_ID}/dns_records`, {
    method: "POST",
    body: JSON.stringify(body),
  });
  return data.result;
}

async function cfDeleteDNS(id) {
  const data = await cfFetch(`/zones/${CF_ZONE_ID}/dns_records/${id}`, { method: "DELETE" });
  return data.result;
}

// ----- Auth endpoints -----
// Signup: requires admin pin; stores hashed password.
app.post("/api/signup", async (req, res) => {
  try {
    const { email, password, pin } = req.body || {};
    if (!email || !password || !pin) {
      return res.status(400).json({ ok: false, error: "missing_fields" });
    }
    if (!ALLOWED_PINS.has(String(pin))) {
      return res.status(403).json({ ok: false, error: "invalid_pin" });
    }
    const existing = DB.users.find((u) => u.email.toLowerCase() === String(email).toLowerCase());
    if (existing) return res.status(409).json({ ok: false, error: "email_exists" });

    const hash = await bcrypt.hash(password, 10);
    const user = {
      id: crypto.randomUUID(),
      email,
      passHash: hash,
      createdAt: Date.now(),
      // attach which pin was used (audit)
      pinUsed: String(pin),
    };
    DB.users.push(user);
    saveDB();

    req.session.userId = user.id;
    res.json({ ok: true, user: { id: user.id, email: user.email } });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// Signin
app.post("/api/signin", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const user = DB.users.find((u) => u.email.toLowerCase() === String(email).toLowerCase());
    if (!user) return res.status(401).json({ ok: false, error: "invalid_creds" });
    const ok = await bcrypt.compare(password, user.passHash);
    if (!ok) return res.status(401).json({ ok: false, error: "invalid_creds" });
    req.session.userId = user.id;
    res.json({ ok: true, user: { id: user.id, email: user.email } });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.post("/api/signout", (req, res) => {
  req.session = null;
  res.json({ ok: true });
});

app.get("/api/me", (req, res) => {
  const user = DB.users.find((u) => u.id === req.session?.userId);
  res.json({ ok: true, user: user ? { id: user.id, email: user.email } : null });
});

// ----- DNS utilities -----
// Check if label is available within ROOT_DOMAIN in Cloudflare AND if it resolves publicly.
app.get("/api/dns/check", async (req, res) => {
  try {
    const q = (req.query.name || "").trim().toLowerCase();
    if (!q) return res.status(400).json({ ok: false, error: "missing_name" });

    // Normalize: allow full hostname or just label
    const full = q.endsWith("." + ROOT_DOMAIN) ? q : `${q}.${ROOT_DOMAIN}`;

    // 1) Look in Cloudflare zone
    let existing = [];
    if (CF_ZONE_ID && CF_API_TOKEN) {
      existing = await cfListDNS({ name: full });
    }

    // 2) Live DNS resolve (best-effort)
    // Try A, CNAME, TXT
    const live = { a: [], cname: [], txt: [] };
    try {
      live.a = await dns.resolve4(full);
    } catch {}
    try {
      live.cname = await dns.resolveCname(full);
    } catch {}
    try {
      live.txt = await dns.resolveTxt(full);
    } catch {}

    const available = existing.length === 0 && live.a.length === 0 && live.cname.length === 0;

    res.json({
      ok: true,
      name: full,
      available,
      cloudflareRecords: existing,
      live,
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// List DNS records (optionally filter by name or type)
app.get("/api/dns/list", requireAuth, async (req, res) => {
  try {
    if (!CF_ZONE_ID || !CF_API_TOKEN) {
      return res.json({ ok: true, records: [], note: "Cloudflare env not set" });
    }
    const { name, type } = req.query;
    const nameFull =
      name && !String(name).endsWith("." + ROOT_DOMAIN)
        ? `${name}.${ROOT_DOMAIN}`
        : name || undefined;
    const records = await cfListDNS({ name: nameFull, type });
    res.json({ ok: true, records });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// Create DNS record (A, CNAME, TXT)
app.post("/api/dns/create", requireAuth, async (req, res) => {
  try {
    if (!CF_ZONE_ID || !CF_API_TOKEN) {
      return res.status(500).json({ ok: false, error: "cloudflare_env_missing" });
    }
    const { type, name, content, ttl = 300, proxied = false } = req.body || {};
    if (!type || !name || !content) {
      return res.status(400).json({ ok: false, error: "missing_fields" });
    }
    const allowedTypes = new Set(["A", "CNAME", "TXT"]);
    if (!allowedTypes.has(String(type).toUpperCase())) {
      return res.status(400).json({ ok: false, error: "unsupported_type" });
    }
    const fullName = name.endsWith("." + ROOT_DOMAIN) ? name : `${name}.${ROOT_DOMAIN}`;

    // Prevent duplicate exact record
    const existing = await cfListDNS({ name: fullName, type });
    const dup = existing.find((r) => String(r.content).trim() === String(content).trim());
    if (dup) return res.status(409).json({ ok: false, error: "record_exists", record: dup });

    const created = await cfCreateDNS({
      type: String(type).toUpperCase(),
      name: fullName,
      content,
      ttl: Number(ttl) || 300,
      proxied: Boolean(proxied),
    });
    res.json({ ok: true, record: created });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// Delete DNS record by id
app.delete("/api/dns/:id", requireAuth, async (req, res) => {
  try {
    if (!CF_ZONE_ID || !CF_API_TOKEN) {
      return res.status(500).json({ ok: false, error: "cloudflare_env_missing" });
    }
    const { id } = req.params;
    const result = await cfDeleteDNS(id);
    res.json({ ok: true, result });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ----- UI (embedded) -----
const INDEX_HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>GACE • Educational Website Registrar</title>
<meta name="description" content="GACE is an educational website registrar for schools and learning communities." />
<meta property="og:title" content="GACE • Educational Website Registrar" />
<meta property="og:description" content="Register educational subdomains, manage sites, and ship learning portals fast." />
<meta property="og:type" content="website" />
<meta name="theme-color" content="#0e1726" />
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Cdefs%3E%3ClinearGradient id='g' x1='0' y1='0' x2='1' y2='1'%3E%3Cstop stop-color='%2307f'/%3E%3Cstop offset='1' stop-color='%2390f'/%3E%3C/linearGradient%3E%3C/defs%3E%3Crect width='64' height='64' rx='12' fill='url(%23g)'/%3E%3Cpath d='M18 34c0-8 6-14 14-14s14 6 14 14-6 14-14 14c-3 0-6-1-8-3l6-6c1 1 2 1 2 1 3 0 6-3 6-6s-3-6-6-6-6 3-6 6H18z' fill='%23fff'/%3E%3C/svg%3E" />
<style>
:root{
  --bg:#0b1120; --panel:rgba(255,255,255,.06); --panel-2:rgba(255,255,255,.08);
  --stroke:rgba(255,255,255,.12); --text:#e5e7eb; --muted:#a3a3a3;
  --brand-a:#2563eb; --brand-b:#8b5cf6; --accent:#22d3ee; --ok:#22c55e;
  --warn:#f59e0b; --err:#ef4444; --shadow:0 10px 30px rgba(0,0,0,.35);
  --radius-xl:18px; --radius-lg:14px;
}
*{box-sizing:border-box} html,body{height:100%}
body{margin:0;background:
  radial-gradient(1200px 600px at 10% -10%, rgba(37,99,235,0.35), transparent 60%),
  radial-gradient(1000px 800px at 100% 0%, rgba(139,92,246,0.28), transparent 60%),
  linear-gradient(180deg, #0b1120 0%, #0f172a 60%, #0b1120 100%);
  color:var(--text); font:16px/1.55 system-ui,-apple-system,Segoe UI,Roboto,Inter,Arial;
}
a{color:inherit;text-decoration:none}
.container{width:min(1200px,92%); margin-inline:auto}
.glass{background:var(--panel); border:1px solid var(--stroke); backdrop-filter:saturate(140%) blur(8px); box-shadow:var(--shadow)}
.btn{display:inline-flex; align-items:center; gap:.6rem; padding:.75rem 1rem; border-radius:12px; border:1px solid var(--stroke); background:var(--panel-2); color:var(--text); font-weight:600; user-select:none}
.btn[disabled]{cursor:not-allowed; opacity:.7}
.btn.primary{background:linear-gradient(135deg, var(--brand-a), var(--brand-b)); border-color:transparent}
.btn.small{padding:.5rem .75rem; font-weight:600; font-size:.9rem}
.pill{display:inline-flex; align-items:center; gap:.5rem; padding:.35rem .6rem; border-radius:999px; border:1px solid var(--stroke); background:rgba(255,255,255,.05); color:var(--muted); font-weight:600; font-size:.8rem}
header{position:sticky; top:0; z-index:50; backdrop-filter:saturate(160%) blur(8px);
  background:linear-gradient(180deg, rgba(11,17,32,.85), rgba(11,17,32,.55)); border-bottom:1px solid var(--stroke)}
nav{display:flex; align-items:center; justify-content:space-between; padding:.9rem 0}
.brand{display:flex; align-items:center; gap:.7rem; font-weight:800; letter-spacing:.4px}
.brand svg{width:28px; height:28px}
.navlinks{display:flex; gap:1rem; align-items:center}
.navlinks a{color:var(--muted); padding:.5rem .6rem; border-radius:10px}
.navlinks a:hover{background:rgba(255,255,255,.06); color:var(--text)}
.hero{padding:clamp(40px, 8vw, 120px) 0 72px; position:relative}
.hero h1{font-size:clamp(32px, 5vw, 56px); line-height:1.05; margin:0 0 16px; letter-spacing:-.02em}
.hero p{color:var(--muted); font-size:clamp(16px, 2.2vw, 20px); margin:0 0 28px}
.hero .cta{display:flex; gap:.75rem; flex-wrap:wrap}
.status{display:inline-flex; align-items:center; gap:.5rem; font-weight:700; color:#c7f9d4}
.status-dot{width:8px; height:8px; border-radius:999px; background:var(--ok); box-shadow:0 0 0 3px rgba(34,197,94,.25)}
.grid{display:grid; gap:18px}
.features{padding:36px 0 14px}
.features .card{border-radius:var(--radius-xl); padding:22px; position:relative}
.icon{width:28px; height:28px; display:inline-grid; place-items:center; border-radius:8px; background:linear-gradient(135deg, rgba(34,211,238,.2), rgba(139,92,246,.2)); border:1px solid var(--stroke)}
.muted{color:var(--muted)}
.panel-title{display:flex; align-items:center; justify-content:space-between; margin-bottom:10px}
.domain-search{display:flex; gap:10px; align-items:center}
.domain-search input{flex:1; padding:14px 16px; border-radius:12px; background:rgba(255,255,255,.07); border:1px solid var(--stroke); color:var(--text)}
.section{padding:80px 0}
.section h2{font-size:clamp(24px,3.2vw,36px); letter-spacing:-.01em; margin:0 0 12px}
.section p.lead{margin:0 0 30px; color:var(--muted)}
.pricing .plan{border-radius:var(--radius-xl); padding:26px}
.plan h3{margin:0 0 8px}
.plan .price{font-size:34px; font-weight:800; margin:6px 0 10px}
.plan ul{list-style:none; padding:0; margin:12px 0 18px}
.plan li{margin:10px 0; color:var(--muted)}
.steps{counter-reset: step}
.steps .step{padding:18px; border-radius:16px; position:relative}
.steps .step::before{counter-increment: step; content: counter(step); position:absolute; inset:auto auto 100% 0; transform:translateY(-10px); background:linear-gradient(135deg, var(--brand-a), var(--brand-b)); color:white; border-radius:10px; padding:4px 10px; font-weight:700; font-size:.85rem}
.policy{border-left:4px solid var(--brand-b); padding-left:16px}
footer{padding:48px 0 60px; border-top:1px solid var(--stroke); margin-top:60px}
.cols{display:grid; grid-template-columns: repeat(12, 1fr); gap:18px}
.col-4{grid-column: span 4}
.col-6{grid-column: span 6}
.col-12{grid-column: span 12}
@media (max-width: 900px){
  .cols{grid-template-columns: repeat(6, 1fr)}
  .col-6,.col-4{grid-column: span 6}
}
@media (max-width: 640px){
  .cols{grid-template-columns: repeat(4, 1fr)}
  .col-4,.col-6{grid-column: span 4}
  .hero .cta{flex-direction:column; align-items:stretch}
}
.mesh{position:absolute; inset:0; background-image:radial-gradient(rgba(255,255,255,.06) 1px, transparent 1px); background-size: 22px 22px; mask-image: radial-gradient(70% 40% at 50% 0%, black, transparent)}
.toast{position:fixed; left:50%; bottom:24px; transform:translateX(-50%) translateY(20px); opacity:0; transition:.25s ease; background:#101828; color:#f1f5f9; padding:12px 14px; border-radius:12px; border:1px solid var(--stroke); box-shadow:var(--shadow); font-weight:600; z-index:999}
.toast.show{opacity:1; transform:translateX(-50%) translateY(0)}
@keyframes spin{to{transform:rotate(360deg)}}
.spinner{width:18px;height:18px;border:3px solid rgba(255,255,255,.25);border-top-color:#fff;border-radius:50%;animation:spin 1s linear infinite}
.inline{display:inline-flex;gap:10px;align-items:center}
.overlay{position:fixed; inset:0; background:rgba(11,17,32,.6); backdrop-filter: blur(6px); display:none; align-items:center; justify-content:center; z-index:1000}
.overlay.show{display:flex}
.overlay .panel{background:var(--panel); border:1px solid var(--stroke); border-radius:16px; box-shadow:var(--shadow); padding:22px; width:min(520px,92%)}
.overlay h3{margin:0 0 8px}
.overlay p{margin:0 0 14px; color:var(--muted)}
.modal{position:fixed; inset:0; background:rgba(11,17,32,.6); backdrop-filter: blur(6px); display:none; align-items:center; justify-content:center; z-index:1000}
.modal.show{display:flex}
.modal .card{background:var(--panel); border:1px solid var(--stroke); border-radius:18px; box-shadow:var(--shadow); width:min(560px, 94%); padding:22px}
.tabs{display:flex; gap:8px; margin-bottom:14px}
.tab{padding:.5rem .8rem; border:1px solid var(--stroke); border-radius:10px; cursor:pointer; user-select:none}
.tab.active{background:linear-gradient(135deg, var(--brand-a), var(--brand-b)); border-color:transparent; color:white}
.field{display:grid; gap:6px; margin:10px 0}
.field input, .field select, .field textarea{padding:12px 14px; border-radius:12px; border:1px solid var(--stroke); background:rgba(255,255,255,.06); color:var(--text)}
.row{display:flex; gap:10px}
.table{width:100%; border-collapse:separate; border-spacing:0 8px}
.table th{color:#cbd5e1; font-weight:700; text-align:left; font-size:.9rem; padding:6px 8px}
.table td{padding:10px 8px; background:rgba(255,255,255,.04); border:1px solid var(--stroke)}
.table tr td:first-child{border-radius:12px 0 0 12px}
.table tr td:last-child{border-radius:0 12px 12px 0}
.badge{font-size:.75rem; padding:.25rem .5rem; border-radius:8px; border:1px solid var(--stroke); background:rgba(255,255,255,.06)}
.danger{color:#fecaca}
</style>
</head>
<body>
<header>
  <div class="container">
    <nav>
      <a class="brand" href="#home" aria-label="GACE home">
        <svg viewBox="0 0 64 64" aria-hidden="true"><defs><linearGradient id="lg" x1="0" y1="0" x2="1" y2="1"><stop stop-color="#22d3ee"/><stop offset="1" stop-color="#8b5cf6"/></linearGradient></defs><rect width="64" height="64" rx="14" fill="url(#lg)"/><path d="M18 34c0-8 6-14 14-14s14 6 14 14-6 14-14 14c-3 0-6-1-8-3l6-6c1 1 2 1 2 1 3 0 6-3 6-6s-3-6-6-6-6 3-6 6H18z" fill="#fff"/></svg>
        <span>GACE</span><span class="pill">Edu Registrar</span>
      </a>
      <div class="navlinks">
        <a href="#features">Features</a>
        <a href="#pricing">Pricing</a>
        <a href="#docs">Docs</a>
        <a href="#policy">Policy</a>
        <a href="#support">Support</a>
        <button class="btn small" id="btnSignin">Sign in</button>
        <button class="btn small primary" id="btnSignup">Create school</button>
      </div>
    </nav>
  </div>
</header>

<section id="home" class="hero">
  <div class="mesh" aria-hidden="true"></div>
  <div class="container">
    <div class="cols">
      <div class="col-6">
        <span class="pill">Status <span class="status"><span class="status-dot"></span>All systems operational</span></span>
        <h1>Register educational&nbsp;subdomains and launch learning portals in minutes.</h1>
        <p>GACE is a lightweight registrar for schools, districts, and learning communities.</p>
        <div class="cta">
          <button class="btn primary" id="ctaSignup">Get started — it’s free</button>
          <button class="btn" id="ctaSignin">View dashboard</button>
        </div>
      </div>
      <div class="col-6">
        <div class="glass" style="border-radius:var(--radius-xl); padding:18px;">
          <div class="panel-title"><strong>Subdomain search</strong></div>
          <div class="domain-search">
            <input id="domainInput" type="text" placeholder="e.g. westside-high.${ROOT_DOMAIN}" />
            <button id="domainCheck" class="btn">Check</button>
          </div>
          <div id="domainResult" style="margin-top:12px; min-height:28px"></div>
          <p class="muted" style="margin-top:10px">Instant SSL • Global edge • Student privacy oriented • Zero-code DNS presets</p>
        </div>
      </div>
    </div>
  </div>
</section>

<!-- Dashboard -->
<section id="dashboard" class="section" style="display:none">
  <div class="container">
    <h2>Dashboard</h2>
    <p class="lead">Manage DNS records on <strong>${ROOT_DOMAIN}</strong></p>

    <div class="cols">
      <div class="col-6">
        <div class="glass" style="border-radius:var(--radius-xl); padding:22px">
          <h3 style="margin-top:0">Create DNS record</h3>
          <div class="field">
            <label>Type</label>
            <select id="recType">
              <option>A</option>
              <option>CNAME</option>
              <option>TXT</option>
            </select>
          </div>
          <div class="field">
            <label>Name (label or FQDN)</label>
            <input id="recName" placeholder="sub or sub.${ROOT_DOMAIN}" />
          </div>
          <div class="field">
            <label>Content</label>
            <input id="recContent" placeholder="IPv4 for A, hostname for CNAME, value for TXT" />
          </div>
          <div class="row">
            <div class="field" style="flex:1">
              <label>TTL (seconds)</label>
              <input id="recTTL" type="number" min="60" value="300" />
            </div>
            <div class="field" style="flex:1">
              <label>Proxied (only for A/CNAME)</label>
              <select id="recProxied">
                <option value="false">false</option>
                <option value="true">true</option>
              </select>
            </div>
          </div>
          <div class="row">
            <button class="btn primary" id="btnCreate">Create</button>
            <button class="btn" id="btnReload">Reload records</button>
            <button class="btn" id="btnSignout">Sign out</button>
          </div>
          <div id="createMsg" class="muted" style="margin-top:8px"></div>
        </div>
      </div>
      <div class="col-6">
        <div class="glass" style="border-radius:var(--radius-xl); padding:22px">
          <h3 style="margin-top:0">Records</h3>
          <table class="table" id="recordsTable">
            <thead><tr>
              <th>Type</th><th>Name</th><th>Content</th><th>TTL</th><th>Proxied</th><th>Actions</th>
            </tr></thead>
            <tbody></tbody>
          </table>
        </div>
      </div>
    </div>

  </div>
</section>

<!-- Toast -->
<div id="toast" class="toast" role="status" aria-live="polite"></div>

<!-- Loading overlay -->
<div class="overlay" id="loadingOverlay" aria-modal="true" role="dialog" aria-labelledby="loadingTitle">
  <div class="panel">
    <div class="inline"><div class="spinner" aria-hidden="true"></div><h3 id="loadingTitle" style="margin:0">Working…</h3></div>
    <p id="loadingDesc">Talking to the backend…</p>
  </div>
</div>

<!-- Auth modal -->
<div class="modal" id="authModal" aria-modal="true" role="dialog" aria-labelledby="authTitle">
  <div class="card">
    <div style="display:flex; align-items:center; justify-content:space-between; margin-bottom:6px">
      <h3 id="authTitle" style="margin:0">Welcome</h3>
      <button class="btn small" id="authClose" title="Close" aria-label="Close">✕</button>
    </div>
    <div class="tabs">
      <div class="tab active" id="tabSignIn">Sign in</div>
      <div class="tab" id="tabSignUp">Create account</div>
    </div>
    <form id="authForm">
      <div class="field"
