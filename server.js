// ─────────────────────────────────────────────────────────────────────────────
//  Revival Today — Prayer Wall connector
//
//  What this does:
//    1. Puts the whole site behind ONE shared password (server-side, secure).
//    2. Reads prayer requests from Planning Center / Church Center form 872511.
//    3. Maps each submission to: name · city/state · request · how long ago.
//    4. Shows them on a clean, branded, mobile-friendly page that updates live.
//
//  Your Planning Center keys live ONLY in environment variables on the server.
//  They are never sent to the browser. See .env.example and README.md.
// ─────────────────────────────────────────────────────────────────────────────

import express from "express";
import cookieParser from "cookie-parser";
import crypto from "crypto";

// ── Config (from environment variables) ──────────────────────────────────────
const PCO_APP_ID     = process.env.PCO_APP_ID;        // Planning Center Application ID
const PCO_SECRET     = process.env.PCO_SECRET;        // Planning Center Secret
const PCO_FORM_ID    = process.env.PCO_FORM_ID || "872511";
const SHARED_PASSWORD = process.env.SHARED_PASSWORD;  // the one team password
const SESSION_SECRET  = process.env.SESSION_SECRET || "change-me-please";
const PORT            = process.env.PORT || 3000;
const CACHE_SECONDS   = 60;                            // re-check PC at most once a minute

// For embedding the wall inside Webflow:
//   ALLOWED_ORIGIN = your Webflow site, e.g. https://revivaltodaychurch.com
//   WIDGET_TOKEN   = a secret string the embed sends so only your page can read data
const ALLOWED_ORIGIN  = process.env.ALLOWED_ORIGIN || "";
const WIDGET_TOKEN    = process.env.WIDGET_TOKEN || "";

// Staff prayer requests come from a Google Form. Publish its responses sheet
// to the web as CSV (File → Share → Publish to web → CSV) and put that link
// here. Leave blank until you're ready — the Staff column just stays empty.
const GOOGLE_CSV_URL  = process.env.GOOGLE_CSV_URL || "";

if (!PCO_APP_ID || !PCO_SECRET) {
  console.warn("⚠️  PCO_APP_ID / PCO_SECRET not set — the wall will have no data.");
}
if (!SHARED_PASSWORD) {
  console.warn("⚠️  SHARED_PASSWORD not set — anyone could view the wall.");
}

const PCO_AUTH = "Basic " + Buffer.from(`${PCO_APP_ID}:${PCO_SECRET}`).toString("base64");
const PCO_BASE = "https://api.planningcenteronline.com/people/v2";

const app = express();
app.use(cookieParser());
app.use(express.urlencoded({ extended: false }));

// Allow your Webflow site to read /api/requests from a browser (CORS).
app.use("/api", (req, res, next) => {
  if (ALLOWED_ORIGIN) {
    res.set("Access-Control-Allow-Origin", ALLOWED_ORIGIN);
    res.set("Vary", "Origin");
  }
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

// A request may reach the data either as a logged-in team member (cookie)
// OR from the Webflow embed carrying the correct widget token.
function allowData(req, res, next) {
  if (req.cookies.rt_auth === GOOD_COOKIE) return next();
  if (WIDGET_TOKEN && req.query.key === WIDGET_TOKEN) return next();
  if (!SHARED_PASSWORD && !WIDGET_TOKEN) return next();   // nothing configured -> open
  return res.status(401).json([]);
}

// ── Simple, secure shared-password gate ──────────────────────────────────────
// We set a signed cookie after a correct password. No accounts, just one password.
function sign(value) {
  return crypto.createHmac("sha256", SESSION_SECRET).update(value).digest("hex");
}
const GOOD_COOKIE = "ok." + sign("ok");

function requireLogin(req, res, next) {
  if (!SHARED_PASSWORD) return next();            // no password configured -> open
  if (req.cookies.rt_auth === GOOD_COOKIE) return next();
  return res.redirect("/login");
}

app.get("/login", (req, res) => res.send(loginPage(false)));

app.post("/login", (req, res) => {
  const ok = SHARED_PASSWORD &&
    crypto.timingSafeEqual(
      Buffer.from(sign(req.body.password || "")),
      Buffer.from(sign(SHARED_PASSWORD))
    );
  if (ok) {
    res.cookie("rt_auth", GOOD_COOKIE, {
      httpOnly: true, sameSite: "lax",
      secure: true, maxAge: 1000 * 60 * 60 * 12,   // 12 hours
    });
    return res.redirect("/");
  }
  res.status(401).send(loginPage(true));
});

app.get("/logout", (req, res) => { res.clearCookie("rt_auth"); res.redirect("/login"); });

// ── The wall page ────────────────────────────────────────────────────────────
app.get("/", requireLogin, (req, res) => {
  res.type("html").send(WALL_HTML);
});

// ── Data endpoint the page calls to get the requests ─────────────────────────
let cache = { at: 0, data: [] };

app.get("/api/requests", allowData, async (req, res) => {
  try {
    if (Date.now() - cache.at < CACHE_SECONDS * 1000) return res.json(cache.data);
    const [congregation, staff] = await Promise.all([fetchPlanningCenter(), fetchGoogle()]);
    const data = [...congregation, ...staff]
      .sort((a, b) => new Date(b.submitted) - new Date(a.submitted));
    cache = { at: Date.now(), data };
    res.json(data);
  } catch (err) {
    console.error("Fetch failed:", err.message);
    // serve last good data if we have it, so the wall never goes blank
    res.json(cache.data);
  }
});

// ── Debug: see the form's field labels (helps map name/city/request) ─────────
app.get("/api/fields", allowData, async (req, res) => {
  const r = await pco(`/forms/${PCO_FORM_ID}/fields?per_page=100`);
  res.json((r.data || []).map(f => ({ id: f.id, label: f.attributes?.label })));
});

// ── Planning Center helpers ──────────────────────────────────────────────────
async function pco(path) {
  const r = await fetch(PCO_BASE + path, { headers: { Authorization: PCO_AUTH } });
  if (!r.ok) throw new Error(`PC ${r.status} on ${path}`);
  return r.json();
}

// Decide which field is the city/state and which is the prayer request,
// by looking at the field labels. Adjust the keyword lists if needed.
function classifyFields(fields) {
  const map = { location: null, request: null, name: null };
  for (const f of fields) {
    const label = (f.attributes?.label || "").toLowerCase();
    if (!map.location && /(city|state|location|where|country|region|address)/.test(label)) map.location = f.id;
    if (!map.request  && /(how can we|how may we|prayer request|pray for)/.test(label))     map.request  = f.id;
    if (!map.name     && /\bname\b/.test(label))                                      map.name     = f.id;
  }
  return map;
}

// Reduce a Planning Center address to just "City, State" for privacy.
// PC address display looks like "Home: 4628 Blackberry Patch Rd Henrico, VA 23231 United States".
function cityState(raw) {
  if (!raw) return "";
  let s = String(raw).replace(/^\s*(home|work|other|mailing)\s*:\s*/i, "").trim();
  if (!s.includes(",")) return s;                         // not a full address — show as-is
  const i = s.indexOf(",");
  let before = s.slice(0, i);
  let after  = s.slice(i + 1);

  // City = whatever follows the last street-suffix token (St, Ave, Rd, ...).
  const suffix = /\b(st|street|ave|avenue|rd|road|dr|drive|blvd|boulevard|ln|lane|way|ct|court|pl|place|cir|circle|trl|trail|hwy|highway|pkwy|parkway|ter|terrace|loop|run|pike|row|sq|square|apt|unit|ste|suite)\b\.?/ig;
  let m, cut = -1, cutLen = 0;
  while ((m = suffix.exec(before))) { cut = m.index; cutLen = m[0].length; }
  let city = cut >= 0 ? before.slice(cut + cutLen) : before;
  city = city.replace(/^[\s,]*[\d#-]+\s*/, "").trim();    // drop leading unit numbers
  if (!city) city = before.trim().split(/\s+/).pop() || "";

  // State = first non-numeric token(s) after the comma, stop at zip / country.
  const stateTokens = [];
  for (const tok of after.trim().split(/\s+/)) {
    if (/\d/.test(tok)) break;
    if (/^(united|usa|us|states|canada|mexico|uk|kingdom)$/i.test(tok)) break;
    stateTokens.push(tok);
  }
  const state = stateTokens.join(" ");
  return state ? `${city}, ${state}` : city;
}

async function fetchPlanningCenter() {
  // 1) field labels -> ids
  const fieldsResp = await pco(`/forms/${PCO_FORM_ID}/fields?per_page=100`);
  const fieldMap = classifyFields(fieldsResp.data || []);

  // 2) latest submissions, with their answers + the submitter
  const subs = await pco(
    `/forms/${PCO_FORM_ID}/form_submissions` +
    `?include=form_submission_values,person&order=-created_at&per_page=50`
  );

  // index the included resources.
  // Group each answer under its OWN submission id (the value points back to its
  // submission), which is more reliable than reading it off the submission.
  const valuesBySub = {}, people = {};
  for (const inc of subs.included || []) {
    if (inc.type === "FormSubmissionValue") {
      const subId = inc.relationships?.form_submission?.data?.id;
      (valuesBySub[subId] = valuesBySub[subId] || []).push(inc);
    }
    if (inc.type === "Person") people[inc.id] = inc;
  }

  const valueFor = (sub, fieldId) => {
    if (!fieldId) return "";
    for (const v of valuesBySub[sub.id] || []) {
      const fid = v?.relationships?.form_field?.data?.id;
      if (fid === fieldId) return v.attributes?.display_value || "";
    }
    return "";
  };

  return (subs.data || []).map(sub => {
    const personId = sub.relationships?.person?.data?.id;
    const person   = personId ? people[personId] : null;
    const personName = person
      ? [person.attributes?.first_name, person.attributes?.last_name].filter(Boolean).join(" ")
      : "";

    const name = valueFor(sub, fieldMap.name) || personName || "Anonymous";
    const location = cityState(valueFor(sub, fieldMap.location));
    const request  = valueFor(sub, fieldMap.request);

    return {
      name: name.trim(),
      location: location.trim(),
      request: request.trim(),
      submitted: sub.attributes?.created_at,
      urgent: /urgent|emergency|surgery|icu|critical/i.test(request),
      source: "Church Center",
    };
  }).filter(r => r.request); // only show entries that actually have a request
}

// ── Staff requests from a published Google Form responses sheet (CSV) ─────────
function parseCSV(text) {
  const rows = []; let row = [], cur = "", q = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) {
      if (c === '"') { if (text[i + 1] === '"') { cur += '"'; i++; } else q = false; }
      else cur += c;
    } else if (c === '"') q = true;
    else if (c === ",") { row.push(cur); cur = ""; }
    else if (c === "\n") { row.push(cur); rows.push(row); row = []; cur = ""; }
    else if (c !== "\r") cur += c;
  }
  if (cur.length || row.length) { row.push(cur); rows.push(row); }
  return rows;
}

async function fetchGoogle() {
  if (!GOOGLE_CSV_URL) return [];                 // staff source not connected yet
  try {
    const r = await fetch(GOOGLE_CSV_URL);
    if (!r.ok) throw new Error("CSV " + r.status);
    const rows = parseCSV(await r.text());
    if (rows.length < 2) return [];
    const headers = rows[0].map(h => h.toLowerCase().trim());
    const find = re => headers.findIndex(h => re.test(h));
    const iName = find(/name/);
    const iLoc  = find(/city|state|location|address|from|where/);
    const iReq  = find(/request|prayer|pray|need|how/);
    const iTime = find(/time|date|stamp/);

    return rows.slice(1).filter(cells => cells.some(c => c && c.trim())).map(cells => {
      const request = (iReq >= 0 ? cells[iReq] : "") || "";
      let submitted = new Date().toISOString();
      if (iTime >= 0 && cells[iTime]) {
        const d = new Date(cells[iTime]);
        if (!isNaN(d)) submitted = d.toISOString();
      }
      return {
        name: (iName >= 0 ? cells[iName] : "").trim(),   // staff form has no name column — leave blank
        location: cityState(iLoc >= 0 ? cells[iLoc] : ""),
        request: request.trim(),
        submitted,
        urgent: /urgent|emergency|surgery|icu|critical/i.test(request),
        source: "Staff",
      };
    }).filter(r => r.request);
  } catch (e) {
    console.error("Google CSV failed:", e.message);
    return [];
  }
}

// ── The wall page (served at "/", behind the password) ───────────────────────
const WALL_HTML = `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Prayer Requests — Revival Today</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Playfair+Display:wght@600;700&display=swap" rel="stylesheet">
<style>
  :root{--rt-black:#1B1B1B;--rt-navy:#213058;--rt-slate:#718093;--rt-red:#C23616;--rt-cream:#F0E6D7;--rt-white:#FFFFFF;}
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:'Inter',-apple-system,Segoe UI,Roboto,sans-serif;background:var(--rt-cream);color:var(--rt-black);line-height:1.55}
  header{text-align:center;padding:34px 20px 28px;background:var(--rt-navy);color:var(--rt-white)}
  header img.logo{height:46px;margin-bottom:16px;filter:brightness(0) invert(1)}
  .eyebrow{font-size:.72rem;letter-spacing:.22em;text-transform:uppercase;color:var(--rt-cream);font-weight:600;opacity:.85}
  header h1{font-family:'Playfair Display',serif;font-weight:700;font-size:2rem;margin-top:6px;color:var(--rt-white)}
  header p.sub{color:var(--rt-cream);font-size:.92rem;margin-top:8px;opacity:.9}
  .statusbar{display:flex;gap:18px;justify-content:center;align-items:center;margin-top:18px;font-size:.78rem;color:var(--rt-cream)}
  .live{display:inline-flex;align-items:center;gap:7px}
  .dot{width:8px;height:8px;border-radius:50%;background:#5bd17e;box-shadow:0 0 0 0 rgba(91,209,126,.6);animation:pulse 2.2s infinite}
  @keyframes pulse{0%{box-shadow:0 0 0 0 rgba(91,209,126,.5)}70%{box-shadow:0 0 0 9px rgba(91,209,126,0)}100%{box-shadow:0 0 0 0 rgba(91,209,126,0)}}
  .count strong{color:var(--rt-white)}
  .wrap{max-width:1040px;margin:0 auto;padding:24px 18px 70px}
  .columns{display:grid;grid-template-columns:1fr 1fr;gap:22px}
  @media(max-width:760px){.columns{grid-template-columns:1fr}}
  .col-head{display:flex;align-items:baseline;justify-content:space-between;
    border-bottom:2px solid #d8cab2;padding:0 2px 8px;margin-bottom:4px}
  .col-head h2{font-family:'Playfair Display',serif;font-size:1.3rem;color:var(--rt-navy)}
  .col-head .n{font-size:.8rem;color:var(--rt-slate);font-weight:600}
  .req{background:var(--rt-white);border:1px solid #e3d8c6;border-left:4px solid var(--rt-navy);border-radius:12px;padding:16px 18px;margin:14px 0;box-shadow:0 1px 3px rgba(27,27,27,.06)}
  .col-staff .req{border-left-color:#3f7d63}
  .req.urgent{border-left-color:var(--rt-red)}
  .req .top{display:flex;justify-content:space-between;align-items:baseline;gap:12px}
  .req .name{font-size:1.1rem;font-weight:700;color:var(--rt-navy)}
  .req .loc{font-size:.8rem;color:var(--rt-slate);font-weight:600;display:block;margin-top:2px}
  .req .ago{font-size:.72rem;color:var(--rt-slate);white-space:nowrap;flex-shrink:0;font-weight:500}
  .req .request{margin-top:11px;font-size:1.0rem;color:var(--rt-black)}
  .badge{display:inline-block;font-size:.64rem;letter-spacing:.08em;text-transform:uppercase;font-weight:700;color:var(--rt-white);background:var(--rt-red);padding:3px 9px;border-radius:999px;margin-bottom:9px}
  .empty{text-align:center;color:var(--rt-slate);padding:36px 14px;font-size:.9rem;border:1px dashed #d8cab2;border-radius:12px;margin-top:14px}
  .req.noname .top{margin-bottom:2px}
  .req.noname .request{margin-top:0;font-weight:500;font-size:1.05rem}
  footer{text-align:center;color:var(--rt-slate);font-size:.78rem;padding:24px 18px 40px}
  footer a{color:var(--rt-red);text-decoration:none;font-weight:600}
  @media(max-width:600px){
    header{padding:24px 16px 20px}
    header img.logo{height:38px;margin-bottom:12px}
    header h1{font-size:1.65rem}
    header p.sub{font-size:.84rem}
    .statusbar{flex-wrap:wrap;gap:10px 16px}
    .wrap{padding:16px 13px 56px}
    .columns{gap:8px}
    .col-head{margin-top:6px}
    .col-head h2{font-size:1.15rem}
    .req{padding:14px 16px;margin:11px 0}
    .req .request{font-size:1rem}
  }
</style></head><body>
  <header>
    <img class="logo" src="https://cdn.prod.website-files.com/69b205b04fb55ca6c4693af9/69b27bf1c55d9cb1a6bb20a6_RTLogo_SideTextBlack%20(1).png" alt="Revival Today">
    <div class="eyebrow">Revival Today</div>
    <h1>Prayer Requests</h1>
    <p class="sub">"The prayer of a righteous person is powerful and effective." — James 5:16</p>
    <div class="statusbar"><span class="live"><span class="dot"></span> Live</span>
      <span class="count"><strong id="num">—</strong> requests</span></div>
  </header>
  <main class="wrap">
    <div class="columns">
      <section class="col-cong">
        <div class="col-head"><h2>Congregation</h2><span class="n" id="n-cong">—</span></div>
        <div id="list-cong"><div class="empty">Loading…</div></div>
      </section>
      <section class="col-staff">
        <div class="col-head"><h2>Staff</h2><span class="n" id="n-staff">—</span></div>
        <div id="list-staff"><div class="empty">Loading…</div></div>
      </section>
    </div>
  </main>
  <footer>Congregation from Church Center · Staff from the staff form · updated <span id="time">—</span> · <a href="/logout">Sign out</a><br>
    Need prayer? Email <a href="mailto:prayer@revivaltoday.com">prayer@revivaltoday.com</a> or text PRAYER to 75767</footer>
<script>
  function esc(s){var d=document.createElement('div');d.textContent=s||'';return d.innerHTML;}
  function ago(iso){if(!iso)return'';var s=Math.floor((Date.now()-new Date(iso))/1000);
    if(s<60)return'just now';if(s<3600)return Math.floor(s/60)+' min ago';
    if(s<86400)return Math.floor(s/3600)+' hr ago';if(s<172800)return'yesterday';
    return Math.floor(s/86400)+' days ago';}
  function card(r){
    var who=r.name?('<span class="name">'+esc(r.name)+'</span>'
      +(r.location?'<span class="loc">'+esc(r.location)+'</span>':'')):'';
    return '<article class="req'+(r.urgent?' urgent':'')+(r.name?'':' noname')+'">'
      +(r.urgent?'<span class="badge">Urgent</span>':'')
      +'<div class="top"><div>'+who+'</div>'
      +'<span class="ago">'+ago(r.submitted)+'</span></div>'
      +'<p class="request">'+esc(r.request)+'</p></article>';}
  function fill(id,items,emptyMsg){
    var el=document.getElementById(id);
    el.innerHTML=items.length?items.map(card).join(''):'<div class="empty">'+emptyMsg+'</div>';}
  function render(items){
    var cong=items.filter(function(r){return r.source!=='Staff';});
    var staff=items.filter(function(r){return r.source==='Staff';});
    document.getElementById('num').textContent=items.length;
    document.getElementById('n-cong').textContent=cong.length;
    document.getElementById('n-staff').textContent=staff.length;
    document.getElementById('time').textContent=new Date().toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'});
    fill('list-cong',cong,'No requests yet.');
    fill('list-staff',staff,'No staff requests yet.');}
  function load(){fetch('/api/requests',{credentials:'same-origin'})
    .then(function(res){if(res.status===401){location.href='/login';return null;}return res.json();})
    .then(function(d){if(d)render(d);}).catch(function(){});}
  load();setInterval(load,30000);
</script></body></html>`;

// ── Tiny inline login page (Revival Today colors) ────────────────────────────
function loginPage(failed) {
  return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Prayer Wall — Sign in</title>
  <style>
    body{margin:0;font-family:-apple-system,Segoe UI,Roboto,sans-serif;
      background:#213058;color:#F0E6D7;display:grid;place-items:center;height:100vh}
    form{background:#F0E6D7;color:#1B1B1B;padding:34px 30px;border-radius:14px;
      width:300px;box-shadow:0 10px 40px rgba(0,0,0,.3);text-align:center}
    h1{font-size:1.25rem;margin:0 0 4px;color:#213058}
    p{margin:0 0 20px;font-size:.85rem;color:#718093}
    input{width:100%;padding:11px;border:1px solid #cdbfa8;border-radius:8px;
      font-size:1rem;margin-bottom:12px;box-sizing:border-box}
    button{width:100%;padding:11px;border:0;border-radius:8px;background:#C23616;
      color:#fff;font-size:1rem;font-weight:600;cursor:pointer}
    .err{color:#C23616;font-size:.82rem;margin-bottom:10px}
  </style></head><body>
  <form method="POST" action="/login">
    <h1>Revival Today</h1>
    <p>Prayer Wall — team access</p>
    ${failed ? '<div class="err">Incorrect password. Try again.</div>' : ""}
    <input type="password" name="password" placeholder="Password" autofocus required>
    <button type="submit">Enter</button>
  </form></body></html>`;
}

app.listen(PORT, () => console.log(`Prayer wall running on http://localhost:${PORT}`));
