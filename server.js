// server.js
import express from "express";
import bodyParser from "body-parser";
import fetch from "node-fetch";
import fs from "fs";

const app = express();
app.use(bodyParser.json());
app.use(express.urlencoded({ extended: true }));

// CONFIG
const PORT = process.env.PORT || 3000;
const CLOUDFLARE_TOKEN = process.env.CF_TOKEN; // put in Render Env vars
const ZONE_ID = process.env.CF_ZONE;           // your Cloudflare Zone ID
const ADMINS = ["2529", "2520"];
const USERS_FILE = "./users.json";

if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, JSON.stringify([]));

// Serve the site (embedded below)
app.get("/", (req, res) => {
  res.send(INDEX_HTML);
});

// Signup endpoint
app.post("/api/signup", async (req, res) => {
  const { email, password, adminPin } = req.body;
  if (!ADMINS.includes(adminPin)) {
    return res.status(403).json({ ok: false, msg: "Invalid admin pin" });
  }

  const users = JSON.parse(fs.readFileSync(USERS_FILE));
  if (users.find(u => u.email === email)) {
    return res.status(400).json({ ok: false, msg: "User already exists" });
  }

  users.push({ email, password, adminPin, domains: [] });
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
  res.json({ ok: true });
});

// Login endpoint
app.post("/api/login", (req, res) => {
  const { email, password } = req.body;
  const users = JSON.parse(fs.readFileSync(USERS_FILE));
  const user = users.find(u => u.email === email && u.password === password);
  if (!user) return res.status(401).json({ ok: false, msg: "Invalid login" });
  res.json({ ok: true, user });
});

// DNS record creation
app.post("/api/dns", async (req, res) => {
  const { type, name, content } = req.body;
  try {
    const cf = await fetch(`https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/dns_records`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${CLOUDFLARE_TOKEN}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ type, name, content, ttl: 1, proxied: false })
    });
    const data = await cf.json();
    if (!data.success) throw new Error(JSON.stringify(data.errors));
    res.json({ ok: true, data });
  } catch (err) {
    res.status(500).json({ ok: false, msg: err.message });
  }
});

// DNS record check
app.get("/api/check/:name", async (req, res) => {
  try {
    const cf = await fetch(`https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/dns_records?name=${req.params.name}`, {
      headers: { Authorization: `Bearer ${CLOUDFLARE_TOKEN}` }
    });
    const data = await cf.json();
    res.json({ ok: true, records: data.result });
  } catch (err) {
    res.status(500).json({ ok: false, msg: err.message });
  }
});

// Dashboard page (basic)
app.get("/dashboard", (req, res) => {
  res.send(`<html><body style="font-family:system-ui;color:#e5e7eb;background:#0b1120;padding:40px">
    <h1>GACE Dashboard</h1>
    <form id="dnsForm">
      <label>Type:</label><select id="type"><option>A</option><option>CNAME</option><option>TXT</option></select><br><br>
      <label>Name:</label><input id="name"/><br><br>
      <label>Content:</label><input id="content"/><br><br>
      <button type="submit">Add DNS Record</button>
    </form>
    <pre id="result"></pre>
    <script>
      document.getElementById('dnsForm').onsubmit=async e=>{
        e.preventDefault();
        const body={type:type.value,name:name.value,content:content.value};
        const res=await fetch('/api/dns',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
        const data=await res.json();
        result.textContent=JSON.stringify(data,null,2);
      }
    </script>
  </body></html>`);
});

// Start server
app.listen(PORT, () => console.log("✅ GACE server running on port", PORT));

const INDEX_HTML = `
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>GACE • Educational Website Registrar</title>
  <style>
    body { font-family: system-ui; background:#0b1120; color:#e5e7eb; text-align:center; margin:0; padding:50px; }
    input,button { padding:10px; border-radius:6px; border:1px solid #333; margin:6px; }
    .panel { background:rgba(255,255,255,.05); display:inline-block; padding:20px; border-radius:12px; }
  </style>
</head>
<body>
  <h1>GACE Registrar</h1>
  <div class="panel">
    <h3>Sign up</h3>
    <input id="email" placeholder="Email"/><br>
    <input id="password" placeholder="Password" type="password"/><br>
    <input id="adminPin" placeholder="Admin PIN"/><br>
    <button id="signup">Sign up</button>
  </div>
  <div class="panel">
    <h3>Login</h3>
    <input id="emailL" placeholder="Email"/><br>
    <input id="passwordL" placeholder="Password" type="password"/><br>
    <button id="login">Login</button>
  </div>
  <script>
    signup.onclick=async()=>{
      const body={email:email.value,password:password.value,adminPin:adminPin.value};
      const r=await fetch('/api/signup',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
      const d=await r.json(); alert(JSON.stringify(d));
      if(d.ok) location.href='/dashboard';
    };
    login.onclick=async()=>{
      const body={email:emailL.value,password:passwordL.value};
      const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
      const d=await r.json(); alert(JSON.stringify(d));
      if(d.ok) location.href='/dashboard';
    };
  </script>
</body>
</html>
`;
