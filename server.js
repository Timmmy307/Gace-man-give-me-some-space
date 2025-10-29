// server.js — GACE Registrar backend (fully working with Cloudflare DNS API)
// Environment variables (Render -> Environment):
// ROOT_DOMAIN=gace.space
// CLOUDFLARE_ZONE_ID=your_zone_id
// CLOUDFLARE_API_TOKEN=your_api_token
// SESSION_SECRET=your_random_secret

import express from "express";
import session from "express-session";
import bodyParser from "body-parser";
import fetch from "node-fetch";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;
const ZONE_ID = process.env.CLOUDFLARE_ZONE_ID;
const CF_TOKEN = process.env.CLOUDFLARE_API_TOKEN;
const ROOT_DOMAIN = process.env.ROOT_DOMAIN || "gace.space";
const SESSION_SECRET = process.env.SESSION_SECRET || "supersecret";
const ADMINS = ["2529", "2520"];
const USERS_FILE = path.join(__dirname, "users.json");

if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, "[]");

app.use(bodyParser.json());
app.use(express.static(__dirname));
app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
  })
);

// ----------- AUTH ROUTES -----------
app.post("/api/signup", (req, res) => {
  const { email, password, adminPin } = req.body;
  const users = JSON.parse(fs.readFileSync(USERS_FILE));

  if (!ADMINS.includes(adminPin))
    return res.status(403).json({ ok: false, msg: "Invalid admin pin" });
  if (users.find((u) => u.email === email))
    return res.status(400).json({ ok: false, msg: "User already exists" });

  users.push({ email, password });
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
  req.session.user = { email };
  res.json({ ok: true, user: { email } });
});

app.post("/api/login", (req, res) => {
  const { email, password } = req.body;
  const users = JSON.parse(fs.readFileSync(USERS_FILE));
  const user = users.find((u) => u.email === email && u.password === password);
  if (!user) return res.status(401).json({ ok: false, msg: "Invalid login" });
  req.session.user = { email };
  res.json({ ok: true, user: { email } });
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get("/api/me", (req, res) => {
  if (!req.session.user) return res.json({ ok: false });
  res.json({ ok: true, user: req.session.user });
});

// ----------- CLOUDFLARE DNS HELPERS -----------
async function cfFetch(path, opts = {}) {
  const r = await fetch(`https://api.cloudflare.com/client/v4/zones/${ZONE_ID}${path}`, {
    headers: { Authorization: `Bearer ${CF_TOKEN}`, "Content-Type": "application/json" },
    ...opts,
  });
  return await r.json();
}

// ----------- DNS ROUTES -----------

// List all DNS records
app.get("/api/records", async (req, res) => {
  if (!req.session.user) return res.status(401).json({ ok: false, msg: "Not logged in" });
  try {
    const data = await cfFetch(`/dns_records`);
    res.json(data);
  } catch (err) {
    res.status(500).json({ ok: false, msg: err.message });
  }
});

// Create a new record
app.post("/api/records", async (req, res) => {
  if (!req.session.user) return res.status(401).json({ ok: false, msg: "Not logged in" });
  const { type, name, content, ttl, proxied } = req.body;
  try {
    // Build a body object and merge any extra fields from the client
    const bodyObj = {};
    if (type !== undefined) bodyObj.type = type;
    if (name !== undefined) bodyObj.name = name;
    if (content !== undefined) bodyObj.content = content;
    if (ttl !== undefined) bodyObj.ttl = ttl;
    if (proxied !== undefined) bodyObj.proxied = proxied;

    // Merge any extra fields (priority, data, etc.) — allow arbitrary passthrough
    // Client can send "extra": { ... } or put fields at top level; both are supported.
    if (req.body.extra && typeof req.body.extra === "object") {
      Object.assign(bodyObj, req.body.extra);
    }
    // Merge any top-level unknown fields as well (safeguarded)
    for (const k of Object.keys(req.body)) {
      if (!["type","name","content","ttl","proxied","extra"].includes(k)) {
        bodyObj[k] = req.body[k];
      }
    }

    const data = await cfFetch(`/dns_records`, {
      method: "POST",
      body: JSON.stringify(bodyObj),
    });
    res.json(data);
  } catch (err) {
    res.status(500).json({ ok: false, msg: err.message });
  }
});

// Update record (edit)
app.patch("/api/records/:id", async (req, res) => {
  if (!req.session.user) return res.status(401).json({ ok: false, msg: "Not logged in" });
  const { type, name, content, ttl, proxied } = req.body;
  try {
    const bodyObj = {};
    if (type !== undefined) bodyObj.type = type;
    if (name !== undefined) bodyObj.name = name;
    if (content !== undefined) bodyObj.content = content;
    if (ttl !== undefined) bodyObj.ttl = ttl;
    if (proxied !== undefined) bodyObj.proxied = proxied;

    if (req.body.extra && typeof req.body.extra === "object") {
      Object.assign(bodyObj, req.body.extra);
    }
    for (const k of Object.keys(req.body)) {
      if (!["type","name","content","ttl","proxied","extra"].includes(k)) {
        bodyObj[k] = req.body[k];
      }
    }

    const data = await cfFetch(`/dns_records/${req.params.id}`, {
      method: "PATCH",
      body: JSON.stringify(bodyObj),
    });
    res.json(data);
  } catch (err) {
    res.status(500).json({ ok: false, msg: err.message });
  }
});

// Delete record
app.delete("/api/records/:id", async (req, res) => {
  if (!req.session.user) return res.status(401).json({ ok: false, msg: "Not logged in" });
  try {
    const data = await cfFetch(`/dns_records/${req.params.id}`, { method: "DELETE" });
    res.json(data);
  } catch (err) {
    res.status(500).json({ ok: false, msg: err.message });
  }
});

// ----------- PAGES -----------
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "index.html")));
app.get("/dashboard", (req, res) => {
  if (!req.session.user) return res.redirect("/index.html");
  res.sendFile(path.join(__dirname, "dashboard.html"));
});

// ----------- START SERVER -----------
app.listen(PORT, () =>
  console.log(`✅ GACE Registrar running at http://localhost:${PORT}`)
);
