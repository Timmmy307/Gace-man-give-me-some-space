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
const CLOUDFLARE_TOKEN = process.env.CF_TOKEN;
const ZONE_ID = process.env.CF_ZONE;
const ADMINS = ["2529", "2520"];
const USERS_FILE = path.join(__dirname, "users.json");

if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, "[]");

app.use(bodyParser.json());
app.use(express.static(__dirname));
app.use(
  session({
    secret: "gace-secret",
    resave: false,
    saveUninitialized: true,
  })
);

// ROUTES
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "index.html")));
app.get("/dashboard", (req, res) => {
  if (!req.session.user) return res.redirect("/");
  res.sendFile(path.join(__dirname, "dashboard.html"));
});

// API - AUTH
app.post("/api/signup", (req, res) => {
  const { email, password, adminPin } = req.body;
  if (!ADMINS.includes(adminPin)) return res.status(403).json({ ok: false, msg: "Invalid admin pin" });

  const users = JSON.parse(fs.readFileSync(USERS_FILE));
  if (users.find((u) => u.email === email))
    return res.status(400).json({ ok: false, msg: "User already exists" });

  users.push({ email, password, adminPin });
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
  req.session.user = { email };
  res.json({ ok: true });
});

app.post("/api/login", (req, res) => {
  const { email, password } = req.body;
  const users = JSON.parse(fs.readFileSync(USERS_FILE));
  const user = users.find((u) => u.email === email && u.password === password);
  if (!user) return res.status(401).json({ ok: false, msg: "Invalid login" });
  req.session.user = { email };
  res.json({ ok: true });
});

// API - DNS RECORDS
app.get("/api/records", async (req, res) => {
  if (!req.session.user) return res.status(401).json({ ok: false, msg: "Not logged in" });
  try {
    const r = await fetch(`https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/dns_records`, {
      headers: { Authorization: `Bearer ${CLOUDFLARE_TOKEN}` },
    });
    const data = await r.json();
    res.json(data);
  } catch (err) {
    res.status(500).json({ ok: false, msg: err.message });
  }
});

app.post("/api/records", async (req, res) => {
  if (!req.session.user) return res.status(401).json({ ok: false, msg: "Not logged in" });
  const { type, name, content } = req.body;
  try {
    const r = await fetch(`https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/dns_records`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${CLOUDFLARE_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ type, name, content, ttl: 1, proxied: false }),
    });
    const data = await r.json();
    res.json(data);
  } catch (err) {
    res.status(500).json({ ok: false, msg: err.message });
  }
});

app.delete("/api/records/:id", async (req, res) => {
  if (!req.session.user) return res.status(401).json({ ok: false, msg: "Not logged in" });
  try {
    const r = await fetch(
      `https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/dns_records/${req.params.id}`,
      { method: "DELETE", headers: { Authorization: `Bearer ${CLOUDFLARE_TOKEN}` } }
    );
    const data = await r.json();
    res.json(data);
  } catch (err) {
    res.status(500).json({ ok: false, msg: err.message });
  }
});

app.listen(PORT, () => console.log("✅ GACE server running on port", PORT));
