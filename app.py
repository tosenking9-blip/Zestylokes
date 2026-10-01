#!/usr/bin/env python3
"""
Zesty Likes — Single file Flask app
Admin: Zesty / 676767   •   Buy: t.me/zestyji
Host easily: python app.py  +  cloudflared tunnel --url http://localhost:5000
"""
import os, re, json, time, uuid, hmac, sqlite3, hashlib, secrets, threading
import datetime as dt
import urllib.parse, urllib.request, urllib.error
from functools import wraps
from flask import Flask, request, jsonify, redirect, render_template_string, session

# ============================================================
# CONFIG
# ============================================================
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "zesty.db")
SECRET_KEY = "zesty-super-secret-change-me-9f3a7c2b"

ADMIN_USERNAME = "Zesty"
ADMIN_PASSWORD = "676767"
TELEGRAM = "zestyji"
CONTACT = f"https://t.me/{TELEGRAM}"

LIKE_API_BASE = "https://zesty220likes.vercel.app/like"
LIKE_API_KEY  = "SulavOp"

TS_SITE   = "0x4AAAAAAFLICIokx6zHNpTP"
TS_SECRET = "0x4AAAAAAFLICCXoXBACekHvukmgiMglL"
TS_VERIFY = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

PORT = int(os.environ.get("PORT", 5000))

# ============================================================
# FLASK
# ============================================================
app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,  # set True behind HTTPS tunnel
    PERMANENT_SESSION_LIFETIME=dt.timedelta(days=7),
)

# ============================================================
# DB
# ============================================================
DEFAULT_SETTINGS = {
    "globalDailyLimit": 5,
    "cooldownSeconds": 30,
    "apiBase": LIKE_API_BASE,
    "apiKey": LIKE_API_KEY,
    "autoLikeEnabled": True,
    "autoLikePerUserDaily": 3,
    "maintenance": False,
}

def db():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def init_db():
    c = db()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        uid TEXT UNIQUE NOT NULL,
        region TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        daily_limit INTEGER NOT NULL DEFAULT 5,
        used_today INTEGER NOT NULL DEFAULT 0,
        auto_used_today INTEGER NOT NULL DEFAULT 0,
        last_reset_date TEXT,
        last_like_at INTEGER DEFAULT 0,
        auto_like INTEGER DEFAULT 0,
        banned INTEGER DEFAULT 0,
        total_likes INTEGER DEFAULT 0,
        created_at INTEGER
    );
    CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        type TEXT, user_id TEXT, username TEXT, uid TEXT,
        region TEXT, ts INTEGER, success INTEGER, response TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_logs_user ON logs(user_id);
    CREATE INDEX IF NOT EXISTS idx_logs_ts ON logs(ts);
    """)
    for k, v in DEFAULT_SETTINGS.items():
        c.execute("INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)", (k, json.dumps(v)))
    c.commit(); c.close()

def get_settings():
    c = db()
    rows = c.execute("SELECT key, value FROM settings").fetchall()
    c.close()
    s = dict(DEFAULT_SETTINGS)
    for r in rows:
        try: s[r["key"]] = json.loads(r["value"])
        except: s[r["key"]] = r["value"]
    return s

def save_settings(patch):
    c = db()
    for k, v in patch.items():
        if k in DEFAULT_SETTINGS:
            c.execute("INSERT INTO settings(key,value) VALUES(?,?) "
                      "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                      (k, json.dumps(v)))
    c.commit(); c.close()

def log_event(**kw):
    c = db()
    c.execute("INSERT INTO logs(type,user_id,username,uid,region,ts,success,response) "
              "VALUES(?,?,?,?,?,?,?,?)",
              (kw.get("type"), kw.get("user_id"), kw.get("username"),
               kw.get("uid"), kw.get("region"), kw.get("ts", int(time.time()*1000)),
               1 if kw.get("success") else 0, json.dumps(kw.get("response", {}))))
    c.commit(); c.close()

# ============================================================
# AUTH
# ============================================================
def hash_pw(pw, salt=None):
    salt = salt or secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 100_000)
    return f"{salt}:{h.hex()}"

def check_pw(pw, stored):
    try:
        salt, _ = stored.split(":", 1)
        return hmac.compare_digest(hash_pw(pw, salt), stored)
    except: return False

def login_required(fn):
    @wraps(fn)
    def w(*a, **kw):
        if not session.get("uid"):
            if request.path.startswith("/api/"):
                return jsonify(ok=False, error="Please log in."), 401
            return redirect("/login")
        return fn(*a, **kw)
    return w

def admin_required(fn):
    @wraps(fn)
    def w(*a, **kw):
        if not session.get("admin"):
            if request.path.startswith("/api/"):
                return jsonify(ok=False, error="Unauthorized"), 401
            return redirect("/zestyadmin")
        return fn(*a, **kw)
    return w

# ============================================================
# TURNSTILE
# ============================================================
def verify_ts(token, ip=""):
    if not TS_SECRET: return {"ok": True}
    if not token: return {"ok": False, "error": "missing-token"}
    data = urllib.parse.urlencode({
        "secret": TS_SECRET, "response": token, "remoteip": ip,
        "idempotency_key": str(uuid.uuid4()),
    }).encode()
    req = urllib.request.Request(TS_VERIFY, data=data, method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            body = json.loads(r.read().decode())
        if not body.get("success"):
            return {"ok": False, "error": (body.get("error-codes") or ["unknown"])[0]}
        return {"ok": True}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def client_ip():
    return (request.headers.get("CF-Connecting-IP")
            or request.headers.get("X-Forwarded-For","").split(",")[0].strip()
            or request.remote_addr or "")

# ============================================================
# LIKE API
# ============================================================
def send_like(uid, region, key=None, base=None):
    url = (f"{base or LIKE_API_BASE}?uid={urllib.parse.quote(str(uid))}"
           f"&server_name={urllib.parse.quote(str(region))}"
           f"&key={urllib.parse.quote(str(key or LIKE_API_KEY))}")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "ZestyLikes/1.0"})
        with urllib.request.urlopen(req, timeout=20) as r:
            raw = r.read().decode(errors="replace")
        try: data = json.loads(raw)
        except: data = {"status": 0, "raw": raw[:300]}
        return {"ok": data.get("status") == 1, "data": data}
    except Exception as e:
        return {"ok": False, "data": {"status": 0, "error": str(e)}}

# ============================================================
# LIMITS
# ============================================================
def today_key(): return dt.datetime.utcnow().strftime("%Y-%m-%d")

def normalize_user(row):
    u = dict(row)
    t = today_key()
    if u.get("last_reset_date") != t:
        u["used_today"] = 0; u["auto_used_today"] = 0; u["last_reset_date"] = t
        c = db()
        c.execute("UPDATE users SET used_today=0,auto_used_today=0,last_reset_date=? WHERE id=?",
                  (t, u["id"]))
        c.commit(); c.close()
    s = get_settings()
    limit = u.get("daily_limit") or 0
    u["remaining_today"] = max(0, limit - (u.get("used_today") or 0))
    u["remaining_auto"]  = max(0, s["autoLikePerUserDaily"] - (u.get("auto_used_today") or 0))
    return u

def public_user(u): return {k: v for k, v in u.items() if k != "password_hash"}

# ============================================================
# AUTOLIKE ENGINE
# ============================================================
def run_autolike():
    s = get_settings()
    if not s["autoLikeEnabled"]:
        return {"ok": True, "processed": 0, "sent": 0}
    c = db()
    users = [dict(r) for r in c.execute(
        "SELECT * FROM users WHERE auto_like=1 AND banned=0").fetchall()]
    c.close()
    per = int(s["autoLikePerUserDaily"] or 0)
    processed = sent = 0
    for u in users:
        t = today_key()
        if u.get("last_reset_date") != t:
            u["used_today"] = 0; u["auto_used_today"] = 0
            c = db()
            c.execute("UPDATE users SET used_today=0,auto_used_today=0,last_reset_date=? WHERE id=?",
                      (t, u["id"])); c.commit(); c.close()
        need = max(0, per - (u.get("auto_used_today") or 0))
        if need <= 0: continue
        processed += 1
        for _ in range(need):
            r = send_like(u["uid"], u["region"], key=s["apiKey"], base=s["apiBase"])
            if r["ok"]:
                c = db()
                c.execute("UPDATE users SET auto_used_today=auto_used_today+1,"
                          "total_likes=total_likes+1 WHERE id=?", (u["id"],))
                c.commit(); c.close()
                sent += 1
            log_event(type="auto", user_id=u["id"], username=u["username"],
                      uid=u["uid"], region=u["region"], success=r["ok"], response=r["data"])
            time.sleep(1.2)
    return {"ok": True, "processed": processed, "sent": sent}

_thread_started = False
def start_scheduler():
    global _thread_started
    if _thread_started: return
    _thread_started = True
    def loop():
        time.sleep(20)
        last = None
        while True:
            try:
                t = today_key()
                if t != last:
                    print(f"[autolike] {t}: {run_autolike()}")
                    last = t
            except Exception as e:
                print(f"[autolike] error: {e}")
            time.sleep(300)
    threading.Thread(target=loop, daemon=True).start()

# ============================================================
# CSS
# ============================================================
CSS = """
:root{--bg:#0a0e18;--card:#121826;--card2:#182134;--bd:#253049;--tx:#e7edf9;
--mut:#8b98b0;--ac:#6d5cff;--ac2:#00d1a0;--dg:#ff4d6d;--wr:#ffb020}
*{box-sizing:border-box}
body{margin:0;font-family:system-ui,-apple-system,sans-serif;
background:radial-gradient(1200px 600px at 50% -10%,#1b2440,var(--bg)) fixed;
color:var(--tx);min-height:100vh}
a{color:var(--ac2);text-decoration:none}a:hover{text-decoration:underline}
.c{max-width:1120px;margin:0 auto;padding:24px 18px 60px}
.cs{max-width:440px;margin:0 auto;padding:60px 18px}
.nav{display:flex;justify-content:space-between;align-items:center;gap:12px;
padding:14px 18px;border-bottom:1px solid var(--bd);background:rgba(10,14,24,.75);
backdrop-filter:blur(10px);position:sticky;top:0;z-index:40}
.brand{display:flex;gap:10px;align-items:center;font-weight:800}
.dot{width:26px;height:26px;border-radius:8px;
background:linear-gradient(135deg,var(--ac),var(--ac2))}
.nl{display:flex;gap:14px;align-items:center;flex-wrap:wrap}
.card{background:linear-gradient(180deg,var(--card),var(--card2));
border:1px solid var(--bd);border-radius:16px;padding:20px;
box-shadow:0 10px 30px rgba(0,0,0,.25)}
.card+.card{margin-top:18px}
.card h2{margin:0 0 4px;font-size:18px}
.sub{color:var(--mut);font-size:13px;margin-bottom:16px}
.grid{display:grid;gap:16px}
.g2{grid-template-columns:repeat(auto-fit,minmax(260px,1fr))}
.g3{grid-template-columns:repeat(auto-fit,minmax(200px,1fr))}
.g4{grid-template-columns:repeat(auto-fit,minmax(150px,1fr))}
.stat{background:var(--card);border:1px solid var(--bd);border-radius:14px;padding:16px}
.lbl{color:var(--mut);font-size:12px;text-transform:uppercase;letter-spacing:.08em}
.val{font-size:26px;font-weight:800;margin-top:6px}
label{display:block;font-size:13px;color:var(--mut);margin:12px 0 6px}
.input,select{width:100%;padding:11px 13px;border-radius:10px;background:#0d1422;
border:1px solid var(--bd);color:var(--tx);font-size:14px;outline:none;font-family:inherit}
.input:focus{border-color:var(--ac)}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;
padding:11px 18px;border-radius:10px;border:1px solid var(--bd);background:#1a2335;
color:var(--tx);font-weight:600;font-size:14px;cursor:pointer;font-family:inherit;
text-decoration:none}
.btn:hover{background:#223050}.btn:disabled{opacity:.5;cursor:not-allowed}
.bp{background:linear-gradient(135deg,var(--ac),#8a7bff);border:none}
.bs{background:linear-gradient(135deg,#00b487,var(--ac2));border:none;color:#04120d}
.bd{background:#3a1522;border-color:#63203a;color:#ff8fa3}
.bsm{padding:6px 11px;font-size:12.5px;border-radius:8px}
.bb{width:100%}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
.tw{overflow-x:auto;border:1px solid var(--bd);border-radius:12px}
table{width:100%;border-collapse:collapse;font-size:13.5px;min-width:640px}
th,td{padding:10px 12px;text-align:left;border-bottom:1px solid var(--bd);white-space:nowrap}
th{background:#0e1524;color:var(--mut);font-size:12px;text-transform:uppercase}
tr:last-child td{border-bottom:none}
.bdg{display:inline-block;padding:3px 9px;border-radius:999px;font-size:11.5px;font-weight:700}
.bg{background:rgba(0,209,160,.15);color:var(--ac2)}
.br{background:rgba(255,77,109,.15);color:var(--dg)}
.bw{background:rgba(255,176,32,.15);color:var(--wr)}
.bm{background:#1c2436;color:var(--mut)}
.al{padding:11px 14px;border-radius:10px;font-size:13.5px;margin-top:14px}
.ao{background:rgba(0,209,160,.12);border:1px solid rgba(0,209,160,.35);color:#7ff0d2}
.ae{background:rgba(255,77,109,.12);border:1px solid rgba(255,77,109,.35);color:#ffa8b8}
.ai{background:rgba(109,92,255,.12);border:1px solid rgba(109,92,255,.35);color:#b9b1ff}
.tabs{display:flex;gap:8px;margin-bottom:18px}
.tab{flex:1;text-align:center;padding:10px;border-radius:10px;border:1px solid var(--bd);
background:#0d1422;cursor:pointer;font-size:14px;font-weight:600;color:var(--mut)}
.tab.active{background:#1b2740;color:var(--tx);border-color:var(--ac)}
.mut{color:var(--mut)}.mono{font-family:ui-monospace,Menlo,monospace}.ctr{text-align:center}
.hr{height:1px;background:var(--bd);margin:18px 0}
.hero{text-align:center;padding:60px 0 30px}
.hero h1{font-size:clamp(28px,6vw,50px);margin:0 0 14px;line-height:1.1}
.hero p{color:var(--mut);font-size:16px;max-width:620px;margin:0 auto 26px}
.bar{height:6px;background:#0d1422;border-radius:99px;overflow:hidden}
.bar>div{height:100%;background:linear-gradient(90deg,var(--ac),var(--ac2))}
.tsw{margin-top:16px;min-height:65px}
.tg{display:inline-flex;align-items:center;gap:8px;padding:13px 22px;border-radius:12px;
background:linear-gradient(135deg,#229ED9,#1f8cc0);color:#fff;font-weight:700;
font-size:15px;text-decoration:none}
.tg:hover{filter:brightness(1.08);text-decoration:none}
.regions{display:flex;flex-wrap:wrap;gap:6px;margin-top:6px}
.regions label{padding:5px 10px;border:1px solid var(--bd);border-radius:8px;
background:#0d1422;font-size:12.5px;cursor:pointer;color:var(--tx);margin:0}
.regions input{display:none}
.regions input:checked+span{color:var(--ac2);font-weight:700}
"""

def page(title, body):
    return f"""<!doctype html><html><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>{title} • Zesty Likes</title><style>{CSS}</style></head>
<body>{body}</body></html>"""

TS_JS = """<script src="https://challenges.cloudflare.com/turnstile/v0/api.js?onload=onloadTS" async defer></script>"""

REGIONS = ["ind","pk","bd","sg","id","th","vn","br","us","me"]

# ============================================================
# PAGES
# ============================================================
@app.route("/")
def landing():
    return page("Home", f"""
<nav class="nav"><div class="brand"><div class="dot"></div>Zesty Likes</div>
<div class="nl"><a class="btn bsm" href="/login">Login</a>
<a class="btn bsm bp" href="{CONTACT}" target="_blank">Buy Access</a></div></nav>
<div class="c"><div class="hero"><h1>Send Likes Instantly ⚡</h1>
<p>Fast, reliable like delivery with daily limits, autolike, and admin control.</p>
<div class="row" style="justify-content:center">
<a class="tg" href="{CONTACT}" target="_blank">💬 Buy on Telegram @{TELEGRAM}</a>
<a class="btn" href="/login">I have an account</a></div></div>
<div class="card" style="text-align:center">
<h2>🔐 Accounts are invite-only</h2>
<p class="mut">Registrations disabled. Buy a plan to get credentials on Telegram.</p>
<a class="tg" href="{CONTACT}" target="_blank">Contact @{TELEGRAM}</a></div>
<div class="grid g3" style="margin-top:20px">
<div class="stat"><div class="lbl">Daily Limit</div><div class="val">Per ID</div></div>
<div class="stat"><div class="lbl">Autolike</div><div class="val">24/7</div></div>
<div class="stat"><div class="lbl">Protection</div><div class="val">Turnstile</div></div>
</div></div>""")

@app.route("/login")
def login_page():
    return page("Login", f"""
<nav class="nav"><div class="brand"><div class="dot"></div>Zesty Likes</div>
<div class="nl"><a class="btn bsm" href="/">Home</a>
<a class="btn bsm bp" href="{CONTACT}" target="_blank">Buy Access</a></div></nav>
<div class="cs"><div class="card">
<h2>Login</h2><div class="sub">Only admin-created accounts can log in.</div>
<form onsubmit="return go(event)">
<label>Username</label><input class="input" id="u" required autocomplete="username"/>
<label>Password</label><input class="input" id="p" type="password" required/>
<div class="tsw" id="ts"></div>
<button class="btn bp bb" id="b" style="margin-top:16px">Login</button></form>
<div id="m" class="al" style="display:none"></div>
<div class="hr"></div>
<div class="ctr"><h3 style="margin:0 0 8px">No account?</h3>
<p class="mut" style="font-size:14px">Buy access on Telegram.</p>
<a class="tg" href="{CONTACT}" target="_blank">💬 @{TELEGRAM}</a></div>
</div></div>
{TS_JS}
<script>
let tok='',wid=null;
window.onloadTS=function(){{
  if(!window.turnstile)return;
  wid=window.turnstile.render('#ts',{{sitekey:'{TS_SITE}',theme:'dark',
    action:'login',callback:t=>tok=t,
    'expired-callback':()=>tok='','error-callback':()=>tok=''}});
}};
function msg(k,t){{const e=document.getElementById('m');
  e.className='al a'+(k==='ok'?'o':'e');e.textContent=t;e.style.display='block';}}
async function go(e){{e.preventDefault();
  if(!tok){{msg('e','Complete the human verification.');return false;}}
  const b=document.getElementById('b');b.disabled=true;
  try{{
    const r=await fetch('/api/login',{{method:'POST',
      headers:{{'Content-Type':'application/json'}},
      body:JSON.stringify({{username:u.value.trim(),password:p.value,turnstileToken:tok}})}});
    const d=await r.json();
    if(!d.ok){{msg('e',d.error||'Login failed.');
      if(wid!==null)try{{turnstile.reset(wid)}}catch(_){{}}tok='';}}
    else{{msg('ok','Success! Redirecting…');setTimeout(()=>location.href='/dashboard',500);}}
  }}catch(_){{msg('e','Network error.');}}
  b.disabled=false;return false;}}
</script>""")

@app.route("/dashboard")
@login_required
def dashboard():
    c = db()
    row = c.execute("SELECT * FROM users WHERE id=?", (session["uid"],)).fetchone()
    c.close()
    if not row: return redirect("/login")
    u = normalize_user(row)
    return page("Dashboard", f"""
<nav class="nav"><div class="brand"><div class="dot"></div>Zesty Likes</div>
<div class="nl"><span class="mut" style="font-size:13px">Hi, <b style="color:var(--tx)">{u['username']}</b></span>
<button class="btn bsm" onclick="refresh()">Refresh</button>
<button class="btn bsm bd" onclick="logout()">Logout</button></div></nav>
<div class="c"><div id="mt" class="al ae" style="display:none;margin-bottom:16px"></div>
<div class="grid g4" style="margin-bottom:16px">
<div class="stat"><div class="lbl">Likes Today</div><div class="val"><span id="ut">0</span>
<span class="mut" style="font-size:16px">/<span id="lt">0</span></span></div></div>
<div class="stat"><div class="lbl">Remaining</div><div class="val" style="color:var(--ac2)" id="rm">0</div></div>
<div class="stat"><div class="lbl">Total Sent</div><div class="val" id="tt">0</div></div>
<div class="stat"><div class="lbl">Autolike</div><div class="val" id="ast">OFF</div></div>
</div>
<div class="grid g2">
<div class="card"><h2>Send Likes</h2><div class="sub">Enter UID and pick one region.</div>
<label>Player UID</label><input class="input mono" id="uid" inputmode="numeric"/>
<label>Region / Server</label><div class="regions" id="rg"></div>
<div class="bar" style="margin:16px 0 6px"><div id="pg" style="width:0%"></div></div>
<div class="mut" style="font-size:12px"><span id="ut2">0</span> of <span id="lt2">0</span> used today</div>
<button class="btn bp bb" id="lb" style="margin-top:16px" onclick="send()">⚡ Send Like</button>
<div id="m" class="al" style="display:none"></div></div>
<div class="card"><h2>Autolike</h2>
<div class="sub">Auto-delivers likes to your UID daily.</div>
<div class="row" style="justify-content:space-between"><span>Status</span>
<span class="bdg bm" id="ab">INACTIVE</span></div>
<button class="btn bb" id="abtn" style="margin-top:16px" onclick="toggleAuto()">Enable</button>
<div id="ai" class="al ai" style="display:none">Autolike disabled by admin.</div>
<div class="hr"></div><div class="mut" style="font-size:12.5px">
UID: <span class="mono">{u['uid']}</span><br/>Region: <span class="mono">{u['region']}</span></div>
</div></div>
<div class="card"><h2>Recent Activity</h2><div class="sub">Last 15 requests.</div>
<div class="tw"><table><thead><tr><th>Time</th><th>Type</th><th>UID</th><th>Region</th>
<th>Status</th><th>Nickname</th></tr></thead><tbody id="hb">
<tr><td colspan="6" class="ctr mut">Loading…</td></tr></tbody></table></div></div>
</div>
<script>
const REGIONS={json.dumps(REGIONS)};
let me=null,cd=0,ct=null,st={{}};
function drawRegions(sel){{
  const box=document.getElementById('rg');
  box.innerHTML=REGIONS.map(r=>`<label>
    <input type="radio" name="rg" value="${{r}}" ${{r===sel?'checked':''}}
      onchange="me&&(me.region='${{r}}')"/><span>${{r.toUpperCase()}}</span>
  </label>`).join('');
}}
function show(k,t){{const e=document.getElementById('m');
  e.className='al a'+(k==='ok'?'o':'e');e.textContent=t;e.style.display='block';}}
function render(){{
  if(!me)return;
  document.getElementById('ut').textContent=me.used_today||0;
  document.getElementById('lt').textContent=me.daily_limit||0;
  document.getElementById('ut2').textContent=me.used_today||0;
  document.getElementById('lt2').textContent=me.daily_limit||0;
  document.getElementById('rm').textContent=me.remaining_today||0;
  document.getElementById('tt').textContent=me.total_likes||0;
  document.getElementById('uid').value=me.uid;
  const pct=me.daily_limit?Math.min(100,((me.used_today||0)/me.daily_limit)*100):0;
  document.getElementById('pg').style.width=pct+'%';
  const on=!!me.auto_like;
  const b=document.getElementById('ab');
  b.className='bdg '+(on?'bg':'bm');b.textContent=on?'ACTIVE':'INACTIVE';
  document.getElementById('ast').textContent=on?'ON':'OFF';
  document.getElementById('ast').style.color=on?'var(--ac2)':'var(--mut)';
  const ab=document.getElementById('abtn');
  ab.textContent=on?'Disable Autolike':'Enable Autolike';
  ab.className='btn bb '+(on?'bd':'bs');
  const lb=document.getElementById('lb');
  lb.disabled=cd>0||(me.remaining_today||0)<=0;
  lb.textContent=cd>0?('Cooldown '+cd+'s'):'⚡ Send Like';
}}
async function refresh(){{
  const r=await fetch('/api/me',{{cache:'no-store'}});
  if(r.status===401){{location.href='/login';return;}}
  const d=await r.json();if(!d.ok)return;
  me=d.user;st=d.settings||{{}};
  if(!document.getElementById('rg').children.length)drawRegions(me.region);
  render();drawHist(d.history||[]);
  document.getElementById('ai').style.display=st.autoLikeEnabled===false?'block':'none';
  document.getElementById('abtn').disabled=st.autoLikeEnabled===false;
  document.getElementById('mt').style.display=st.maintenance?'block':'none';
}}
function drawHist(h){{
  const b=document.getElementById('hb');
  if(!h.length){{b.innerHTML='<tr><td colspan="6" class="ctr mut">No activity yet.</td></tr>';return;}}
  b.innerHTML=h.map(l=>{{
    const tb=l.type==='auto'?'bw':'bm', sb=l.success?'bg':'br';
    const nk=(l.response&&l.response.PlayerNickname)||'—';
    return `<tr><td class="mut">${{new Date(l.ts).toLocaleString()}}</td>
      <td><span class="bdg ${{tb}}">${{l.type}}</span></td>
      <td class="mono">${{l.uid}}</td><td>${{l.region}}</td>
      <td><span class="bdg ${{sb}}">${{l.success?'OK':'FAIL'}}</span></td>
      <td class="mut">${{nk}}</td></tr>`;
  }}).join('');
}}
function startCD(s){{if(!s)return;cd=s;render();
  clearInterval(ct);ct=setInterval(()=>{{cd=Math.max(0,cd-1);render();
    if(cd<=0)clearInterval(ct);}},1000);}}
async function send(){{
  const uid=document.getElementById('uid').value.trim();
  const reg=(document.querySelector('input[name=rg]:checked')||{{}}).value||me.region;
  document.getElementById('m').style.display='none';
  const r=await fetch('/api/like',{{method:'POST',
    headers:{{'Content-Type':'application/json'}},
    body:JSON.stringify({{uid,region:reg}})}});
  const d=await r.json();
  if(!d.ok){{show('e',d.error||'Failed.');if(r.status===429&&d.wait)startCD(d.wait);}}
  else{{const a=d.api||{{}};
    show('ok',`✅ Sent! ${{a.PlayerNickname||'—'}} • Likes: ${{a.LikesafterCommand??'—'}} • Left: ${{d.remaining_today}}`);}}
  refresh();
}}
async function toggleAuto(){{
  const r=await fetch('/api/me',{{method:'PATCH',
    headers:{{'Content-Type':'application/json'}},
    body:JSON.stringify({{autoLike:!me.auto_like}})}});
  const d=await r.json();if(d.ok){{me=d.user;render();}}
}}
async function logout(){{await fetch('/api/logout',{{method:'POST'}});location.href='/login';}}
refresh();setInterval(refresh,30000);
</script>""")

@app.route("/zestyadmin")
def admin_page():
    if not session.get("admin"):
        return page("Admin Login", f"""
<nav class="nav"><div class="brand"><div class="dot"></div>Zesty Admin</div>
<div class="nl"><a class="btn bsm" href="/">Home</a></div></nav>
<div class="cs"><div class="card">
<h2>Admin Login</h2><div class="sub">Restricted area.</div>
<form onsubmit="return go(event)">
<label>Username</label><input class="input" id="u" required autocomplete="off"/>
<label>Password</label><input class="input" id="p" type="password" required/>
<div class="tsw" id="ts"></div>
<button class="btn bp bb" id="b" style="margin-top:16px">Enter Admin Panel</button></form>
<div id="m" class="al" style="display:none"></div></div></div>
{TS_JS}
<script>
let tok='',wid=null;
window.onloadTS=function(){{
  if(!window.turnstile)return;
  wid=window.turnstile.render('#ts',{{sitekey:'{TS_SITE}',theme:'dark',
    action:'admin-login',callback:t=>tok=t,
    'expired-callback':()=>tok='','error-callback':()=>tok=''}});
}};
function msg(k,t){{const e=document.getElementById('m');
  e.className='al a'+(k==='ok'?'o':'e');e.textContent=t;e.style.display='block';}}
async function go(e){{e.preventDefault();
  if(!tok){{msg('e','Complete verification.');return false;}}
  const b=document.getElementById('b');b.disabled=true;
  try{{
    const r=await fetch('/api/admin/login',{{method:'POST',
      headers:{{'Content-Type':'application/json'}},
      body:JSON.stringify({{username:u.value.trim(),password:p.value,turnstileToken:tok}})}});
    const d=await r.json();
    if(d.ok)location.href='/zestyadmin';
    else{{msg('e',d.error||'Failed.');if(wid!==null)try{{turnstile.reset(wid)}}catch(_){{}}tok='';}}
  }}catch(_){{msg('e','Network error.');}}
  b.disabled=false;return false;}}
</script>""")
    return page("Admin Panel", f"""
<nav class="nav"><div class="brand"><div class="dot"></div>Zesty Admin</div>
<div class="nl"><a class="btn bsm" href="/auto_logs_all_users">Auto Logs</a>
<button class="btn bsm" onclick="load()">Refresh</button>
<button class="btn bsm bd" onclick="logout()">Logout</button></div></nav>
<div class="c"><div id="msg" class="al" style="display:none;margin-bottom:16px"></div>
<div class="tabs">
<div class="tab active" data-t="ov" onclick="tab('ov')">Overview</div>
<div class="tab" data-t="us" onclick="tab('us')">Users</div>
<div class="tab" data-t="cr" onclick="tab('cr')">Create</div>
<div class="tab" data-t="se" onclick="tab('se')">Settings</div>
<div class="tab" data-t="lo" onclick="tab('lo')">Logs</div></div>

<div id="t-ov"><div class="grid g4" style="margin-bottom:16px">
<div class="stat"><div class="lbl">Total Users</div><div class="val" id="s1">0</div></div>
<div class="stat"><div class="lbl">Likes Today</div><div class="val" id="s2">0</div></div>
<div class="stat"><div class="lbl">Likes Total</div><div class="val" id="s3">0</div></div>
<div class="stat"><div class="lbl">Autolike Users</div><div class="val" id="s4">0</div></div>
</div><div class="grid g4" style="margin-bottom:16px">
<div class="stat"><div class="lbl">Banned</div><div class="val" style="color:var(--dg)" id="s5">0</div></div>
<div class="stat"><div class="lbl">Auto Today</div><div class="val" id="s6">0</div></div>
<div class="stat"><div class="lbl">Failed Today</div><div class="val" style="color:var(--wr)" id="s7">0</div></div>
<div class="stat"><div class="lbl">Success Rate</div><div class="val" id="s8">100%</div></div>
</div><div class="card"><h2>Autolike Engine</h2>
<div class="sub">Runs daily. You can also trigger manually.</div>
<button class="btn bp" onclick="runCron()">▶ Run Autolike Now</button></div></div>

<div id="t-us" style="display:none"><div class="card"><h2>Users</h2>
<div class="sub">Manage limits, autolike, bans, and passwords.</div>
<div class="tw"><table><thead><tr><th>Username</th><th>UID</th><th>Region</th>
<th>Used/Limit</th><th>Total</th><th>Autolike</th><th>Status</th><th>Actions</th></tr></thead>
<tbody id="ub"></tbody></table></div></div></div>

<div id="t-cr" style="display:none"><div class="card"><h2>Create User</h2>
<div class="sub">Only admin can create accounts (after payment on Telegram).</div>
<div class="grid g2"><div>
<label>Username</label><input class="input" id="cu" placeholder="buyer_001"/>
<label>Password</label><input class="input" id="cp" placeholder="min 6 chars"/>
<label>Player UID</label><input class="input mono" id="cid" placeholder="6662785176" inputmode="numeric"/>
<label>Region</label><select class="input" id="crg">{''.join(f'<option value="{r}">{r.upper()}</option>' for r in REGIONS)}</select>
</div><div>
<label>Daily limit</label><input class="input" id="cl" type="number" value="5" min="0"/>
<label>Enable autolike</label><select class="input" id="ca">
<option value="0">No</option><option value="1">Yes</option></select>
<div class="hr"></div>
<button class="btn bp bb" onclick="createUser()">+ Create User</button>
<button class="btn bb" style="margin-top:10px" onclick="rand()">🎲 Random Credentials</button>
<div id="co" class="al ai" style="display:none;white-space:pre-wrap"></div>
</div></div></div></div>

<div id="t-se" style="display:none"><div class="grid g2">
<div class="card"><h2>Limits & Cooldown</h2>
<label>Default daily limit</label><input class="input" type="number" id="sg"/>
<label>Cooldown (seconds)</label><input class="input" type="number" id="sc"/>
<label>Autolikes per user/day</label><input class="input" type="number" id="sa"/>
<div class="hr"/>
<div class="row" style="justify-content:space-between;margin:10px 0">
<span>Autolike system</span><button class="btn bsm" id="ta" onclick="tog('autoLikeEnabled')">—</button></div>
<div class="row" style="justify-content:space-between;margin:10px 0">
<span>Maintenance</span><button class="btn bsm" id="tm" onclick="tog('maintenance')">—</button></div></div>
<div class="card"><h2>API</h2>
<label>API Base URL</label><input class="input" id="sb"/>
<label>API Key</label><input class="input" id="sk"/>
<button class="btn bp bb" style="margin-top:16px" onclick="saveSet()">Save Settings</button>
</div></div></div>

<div id="t-lo" style="display:none"><div class="card"><h2>All Logs</h2>
<div class="sub">Latest 200 across all users.</div>
<div class="tw"><table><thead><tr><th>Time</th><th>User</th><th>Type</th><th>UID</th>
<th>Region</th><th>Status</th><th>Nickname</th></tr></thead><tbody id="lob"></tbody></table></div>
</div></div></div>
<script>
let S=null;
function tab(t){{
  document.querySelectorAll('.tab').forEach(e=>e.classList.toggle('active',e.dataset.t===t));
  ['ov','us','cr','se','lo'].forEach(x=>
    document.getElementById('t-'+x).style.display=x===t?'':'none');
}}
function msg(k,t){{const e=document.getElementById('msg');
  e.className='al a'+(k==='ok'?'o':k==='info'?'i':'e');e.textContent=t;
  e.style.display='block';setTimeout(()=>e.style.display='none',4000);}}
async function load(){{
  const r=await fetch('/api/admin/data',{{cache:'no-store'}});
  if(r.status===401){{location.href='/zestyadmin';return;}}
  const d=await r.json();if(!d.ok)return;S=d;render();
}}
function render(){{
  const s=S.stats;
  ['s1','s2','s3','s4','s5','s6','s7'].forEach((id,i)=>{{
    document.getElementById(id).textContent=[s.totalUsers,s.likesToday,s.likesAllTime,
      s.autoUsers,s.bannedUsers,s.autoToday,s.failedToday][i];}});
  document.getElementById('s8').textContent=s.successRate+'%';
  const st=S.settings;
  document.getElementById('sg').value=st.globalDailyLimit;
  document.getElementById('sc').value=st.cooldownSeconds;
  document.getElementById('sa').value=st.autoLikePerUserDaily;
  document.getElementById('sb').value=st.apiBase||'';
  document.getElementById('sk').value=st.apiKey||'';
  const ta=document.getElementById('ta');
  ta.textContent=st.autoLikeEnabled?'ENABLED':'DISABLED';
  ta.className='btn bsm '+(st.autoLikeEnabled?'bs':'');
  const tm=document.getElementById('tm');
  tm.textContent=st.maintenance?'ENABLED':'DISABLED';
  tm.className='btn bsm '+(st.maintenance?'bs':'');
  const ub=document.getElementById('ub');
  if(!S.users.length)ub.innerHTML='<tr><td colspan="8" class="ctr mut">No users yet.</td></tr>';
  else ub.innerHTML=S.users.map(u=>`<tr>
    <td><b>${{u.username}}</b></td><td class="mono">${{u.uid}}</td><td>${{u.region}}</td>
    <td>${{u.used_today}}/${{u.daily_limit}}</td><td>${{u.total_likes||0}}</td>
    <td><button class="btn bsm ${{u.auto_like?'bs':''}}"
      onclick="upd('${{u.id}}',{{autoLike:${{u.auto_like?'false':'true'}}}})">${{u.auto_like?'ON':'OFF'}}</button></td>
    <td><span class="bdg ${{u.banned?'br':'bg'}}">${{u.banned?'BANNED':'ACTIVE'}}</span></td>
    <td><div class="row">
    <button class="btn bsm" onclick="pr('${{u.id}}',${{u.daily_limit}})">Limit</button>
    <button class="btn bsm" onclick="ppw('${{u.id}}','${{u.username}}')">Pass</button>
    <button class="btn bsm" onclick="upd('${{u.id}}',{{banned:${{u.banned?'false':'true'}}}})">${{u.banned?'Unban':'Ban'}}</button>
    <button class="btn bsm" onclick="upd('${{u.id}}',{{resetToday:true}})">Reset</button>
    <button class="btn bsm bd" onclick="del('${{u.id}}','${{u.username}}')">Del</button>
    </div></td></tr>`).join('');
  const lb=document.getElementById('lob');
  if(!S.logs.length)lb.innerHTML='<tr><td colspan="7" class="ctr mut">No logs.</td></tr>';
  else lb.innerHTML=S.logs.map(l=>{{
    const tb=l.type==='auto'?'bw':'bm', sb=l.success?'bg':'br';
    const nk=(l.response&&l.response.PlayerNickname)||'—';
    return `<tr><td class="mut">${{new Date(l.ts).toLocaleString()}}</td>
    <td>${{l.username||'—'}}</td><td><span class="bdg ${{tb}}">${{l.type}}</span></td>
    <td class="mono">${{l.uid}}</td><td>${{l.region}}</td>
    <td><span class="bdg ${{sb}}">${{l.success?'OK':'FAIL'}}</span></td>
    <td class="mut">${{nk}}</td></tr>`;}}).join('');
}}
async function createUser(){{
  const body={{username:cu.value.trim(),password:cp.value,uid:cid.value.trim(),
    region:crg.value,dailyLimit:+cl.value||0,autoLike:ca.value==='1'}};
  const r=await fetch('/api/admin/user/create',{{method:'POST',
    headers:{{'Content-Type':'application/json'}},body:JSON.stringify(body)}});
  const d=await r.json();
  const o=document.getElementById('co');
  if(!d.ok){{msg('e',d.error||'Failed.');o.style.display='none';return;}}
  msg('ok','User created.');
  o.className='al ao';o.style.display='block';
  o.textContent=`✅ Account created\\n\\nUsername: ${{d.user.username}}\\nPassword: ${{body.password}}\\nUID: ${{d.user.uid}}\\nRegion: ${{d.user.region}}\\nLimit: ${{d.user.daily_limit}}`;
  cp.value='';load();
}}
function rand(){{cu.value='user_'+Math.random().toString(36).slice(2,8);
  cp.value=Math.random().toString(36).slice(2,10);}}
async function saveSet(){{
  const p={{globalDailyLimit:+sg.value,cooldownSeconds:+sc.value,
    autoLikePerUserDaily:+sa.value,apiBase:sb.value,apiKey:sk.value}};
  const r=await fetch('/api/admin/data',{{method:'POST',
    headers:{{'Content-Type':'application/json'}},body:JSON.stringify(p)}});
  const d=await r.json();
  msg(d.ok?'ok':'e',d.ok?'Saved.':'Failed.');load();
}}
async function tog(k){{
  const p={{}};p[k]=!S.settings[k];
  await fetch('/api/admin/data',{{method:'POST',
    headers:{{'Content-Type':'application/json'}},body:JSON.stringify(p)}});
  load();
}}
async function upd(id,patch){{
  await fetch('/api/admin/user',{{method:'POST',
    headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{id,...patch}})}});
  load();
}}
function pr(id,cur){{const v=prompt('New limit:',cur);if(v!==null&&!isNaN(+v))upd(id,{{dailyLimit:+v}});}}
async function ppw(id,name){{
  const v=prompt('New password for "'+name+'" (min 6):');if(v===null)return;
  if(v.length<6){{msg('e','Min 6 chars.');return;}}
  await fetch('/api/admin/user',{{method:'POST',
    headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{id,password:v}})}});
  msg('ok','Password updated.');
}}
async function del(id,name){{if(!confirm('Delete "'+name+'"?'))return;
  await fetch('/api/admin/user?id='+encodeURIComponent(id),{{method:'DELETE'}});load();}}
async function runCron(){{
  msg('info','Running…');
  const r=await fetch('/api/cron/auto-like',{{method:'POST'}});
  const d=await r.json();
  msg(d.ok?'ok':'e',`Processed: ${{d.processed||0}}, Sent: ${{d.sent||0}}`);load();}}
async function logout(){{await fetch('/api/admin/logout',{{method:'POST'}});location.href='/zestyadmin';}}
load();setInterval(load,30000);
</script>""")

@app.route("/auto_logs_all_users")
@admin_required
def auto_logs():
    c = db()
    logs = [dict(r) for r in c.execute(
        "SELECT * FROM logs WHERE type='auto' ORDER BY ts DESC LIMIT 500").fetchall()]
    c.close()
    for l in logs:
        try: l["response"] = json.loads(l["response"]) if l["response"] else {}
        except: l["response"] = {}
    t = today_key()
    agg = {}
    for l in logs:
        k = l.get("user_id") or l.get("username") or "?"
        if k not in agg:
            agg[k] = {"username": l.get("username") or "—", "uid": l.get("uid") or "—",
                      "region": l.get("region") or "—", "today": 0, "today_failed": 0,
                      "total": 0, "last_ts": l["ts"]}
        a = agg[k]; a["total"] += 1
        d = dt.datetime.utcfromtimestamp(l["ts"]/1000).strftime("%Y-%m-%d")
        if d == t:
            if l["success"]: a["today"] += 1
            else: a["today_failed"] += 1
        if l["ts"] > a["last_ts"]: a["last_ts"] = l["ts"]
    rows = sorted(agg.values(), key=lambda x: x["today"], reverse=True)
    for r in rows:
        r["last_str"] = dt.datetime.utcfromtimestamp(r["last_ts"]/1000).strftime("%Y-%m-%d %H:%M")
    raw = []
    for l in logs[:300]:
        raw.append({
            "ts_str": dt.datetime.utcfromtimestamp(l["ts"]/1000).strftime("%Y-%m-%d %H:%M:%S"),
            "username": l.get("username") or "—", "uid": l.get("uid") or "—",
            "region": l.get("region") or "—", "success": bool(l["success"]),
            "nickname": (l["response"] or {}).get("PlayerNickname", "—"),
            "likes_after": (l["response"] or {}).get("LikesafterCommand", "—"),
        })
    rows_html = "".join(f"""<tr><td><b>{r['username']}</b></td>
    <td class="mono">{r['uid']}</td><td>{r['region']}</td>
    <td><span class="bdg bg">{r['today']}</span></td>
    <td><span class="bdg br">{r['today_failed']}</span></td>
    <td>{r['total']}</td><td class="mut">{r['last_str']}</td></tr>""" for r in rows) \
        or '<tr><td colspan="7" class="ctr mut">No autolike activity.</td></tr>'
    raw_html = "".join(f"""<tr><td class="mut">{x['ts_str']}</td>
    <td>{x['username']}</td><td class="mono">{x['uid']}</td><td>{x['region']}</td>
    <td><span class="bdg {'bg' if x['success'] else 'br'}">{'OK' if x['success'] else 'FAIL'}</span></td>
    <td class="mut">{x['nickname']}</td><td>{x['likes_after']}</td></tr>""" for x in raw) \
        or '<tr><td colspan="7" class="ctr mut">No logs.</td></tr>'
    return page("Autolike Logs", f"""
<nav class="nav"><div class="brand"><div class="dot"></div>Autolike Logs</div>
<div class="nl"><a class="btn bsm" href="/zestyadmin">← Admin</a>
<button class="btn bsm" onclick="location.reload()">Refresh</button></div></nav>
<div class="c"><div class="grid g4" style="margin-bottom:16px">
<div class="stat"><div class="lbl">Total Auto Logs</div><div class="val">{len(logs)}</div></div>
<div class="stat"><div class="lbl">Users With Auto</div><div class="val">{len(rows)}</div></div>
<div class="stat"><div class="lbl">Sent Today</div><div class="val" style="color:var(--ac2)">{sum(r['today'] for r in rows)}</div></div>
<div class="stat"><div class="lbl">Failed Today</div><div class="val" style="color:var(--dg)">{sum(r['today_failed'] for r in rows)}</div></div>
</div>
<div class="card"><h2>Daily Summary per User</h2>
<div class="tw"><table><thead><tr><th>User</th><th>UID</th><th>Region</th>
<th>Today</th><th>Failed Today</th><th>Total</th><th>Last Activity</th></tr></thead>
<tbody>{rows_html}</tbody></table></div></div>
<div class="card"><h2>Raw Autolike Log</h2>
<div class="tw"><table><thead><tr><th>Time</th><th>User</th><th>UID</th><th>Region</th>
<th>Status</th><th>Nickname</th><th>Likes After</th></tr></thead>
<tbody>{raw_html}</tbody></table></div></div></div>""")

# ============================================================
# API ROUTES
# ============================================================
@app.route("/api/login", methods=["POST"])
def api_login():
    b = request.get_json(silent=True) or {}
    u = (b.get("username") or "").strip(); p = b.get("password") or ""
    if not (u and p): return jsonify(ok=False, error="Enter credentials."), 400
    cap = verify_ts(b.get("turnstileToken"), client_ip())
    if not cap["ok"]: return jsonify(ok=False, error="Human verification failed."), 400
    c = db()
    row = c.execute("SELECT * FROM users WHERE LOWER(username)=LOWER(?)", (u,)).fetchone()
    c.close()
    if not row or not check_pw(p, row["password_hash"]):
        return jsonify(ok=False, error="Invalid username or password."), 401
    if row["banned"]: return jsonify(ok=False, error="Account suspended."), 403
    session.permanent = True; session["uid"] = row["id"]
    return jsonify(ok=True)

@app.route("/api/logout", methods=["POST"])
def api_logout():
    session.pop("uid", None); return jsonify(ok=True)

@app.route("/api/me")
@login_required
def api_me():
    c = db()
    row = c.execute("SELECT * FROM users WHERE id=?", (session["uid"],)).fetchone()
    if not row: c.close(); return jsonify(ok=False), 404
    u = normalize_user(row)
    hist = c.execute("SELECT * FROM logs WHERE user_id=? ORDER BY ts DESC LIMIT 15",
                     (session["uid"],)).fetchall()
    c.close()
    history = []
    for r in hist:
        d = dict(r)
        try: d["response"] = json.loads(d["response"]) if d["response"] else {}
        except: d["response"] = {}
        history.append(d)
    s = get_settings()
    return jsonify(ok=True, user=public_user(u), history=history,
        settings={"cooldownSeconds": s["cooldownSeconds"],
                  "autoLikePerUserDaily": s["autoLikePerUserDaily"],
                  "autoLikeEnabled": s["autoLikeEnabled"],
                  "maintenance": s["maintenance"]})

@app.route("/api/me", methods=["PATCH"])
@login_required
def api_me_patch():
    b = request.get_json(silent=True) or {}
    s = get_settings(); c = db()
    if "autoLike" in b:
        c.execute("UPDATE users SET auto_like=? WHERE id=?",
                  (1 if (b["autoLike"] and s["autoLikeEnabled"]) else 0, session["uid"]))
    if b.get("uid") and re.fullmatch(r"\d{6,15}", str(b["uid"])):
        c.execute("UPDATE users SET uid=? WHERE id=?", (str(b["uid"]), session["uid"]))
    if b.get("region"):
        c.execute("UPDATE users SET region=? WHERE id=?", (str(b["region"]), session["uid"]))
    c.commit()
    row = c.execute("SELECT * FROM users WHERE id=?", (session["uid"],)).fetchone()
    c.close()
    return jsonify(ok=True, user=public_user(normalize_user(row)))

@app.route("/api/like", methods=["POST"])
@login_required
def api_like():
    b = request.get_json(silent=True) or {}
    s = get_settings(); c = db()
    row = c.execute("SELECT * FROM users WHERE id=?", (session["uid"],)).fetchone()
    if not row: c.close(); return jsonify(ok=False, error="Not found"), 404
    if row["banned"]: c.close(); return jsonify(ok=False, error="Banned"), 403
    if s["maintenance"]: c.close(); return jsonify(ok=False, error="Maintenance"), 503
    u = normalize_user(row); c.close()
    uid = str(b.get("uid") or u["uid"]).strip()
    region = str(b.get("region") or u["region"]).strip()
    if not re.fullmatch(r"\d{6,15}", uid):
        return jsonify(ok=False, error="Invalid UID."), 400
    limit = u["daily_limit"] or s["globalDailyLimit"]
    if (u["used_today"] or 0) >= limit:
        return jsonify(ok=False, error=f"Daily limit reached ({limit}/{limit})."), 429
    cd_ms = int(s["cooldownSeconds"] or 0) * 1000
    elapsed = int(time.time()*1000) - (u["last_like_at"] or 0)
    if cd_ms and elapsed < cd_ms:
        wait = int((cd_ms - elapsed + 999)//1000)
        return jsonify(ok=False, error=f"Cooldown. Wait {wait}s.", wait=wait), 429
    r = send_like(uid, region, key=s["apiKey"], base=s["apiBase"])
    c = db()
    if r["ok"]:
        c.execute("UPDATE users SET used_today=used_today+1,total_likes=total_likes+1,"
                  "last_like_at=? WHERE id=?", (int(time.time()*1000), u["id"]))
        c.commit()
    c.close()
    log_event(type="manual", user_id=u["id"], username=u["username"],
              uid=uid, region=region, success=r["ok"], response=r["data"])
    if not r["ok"]:
        return jsonify(ok=False, error=(r["data"] or {}).get("error") or "API error."), 502
    c = db()
    fresh = c.execute("SELECT * FROM users WHERE id=?", (u["id"],)).fetchone()
    c.close()
    fresh = normalize_user(fresh)
    return jsonify(ok=True, api=r["data"], remaining_today=fresh["remaining_today"],
                   used_today=fresh["used_today"], daily_limit=fresh["daily_limit"])

# ---------- ADMIN API ----------
@app.route("/api/admin/login", methods=["POST"])
def api_admin_login():
    b = request.get_json(silent=True) or {}
    if not verify_ts(b.get("turnstileToken"), client_ip())["ok"]:
        return jsonify(ok=False, error="Human verification failed."), 400
    if b.get("username") != ADMIN_USERNAME or b.get("password") != ADMIN_PASSWORD:
        return jsonify(ok=False, error="Invalid credentials."), 401
    session.permanent = True; session["admin"] = ADMIN_USERNAME
    return jsonify(ok=True)

@app.route("/api/admin/logout", methods=["POST"])
def api_admin_logout():
    session.pop("admin", None); return jsonify(ok=True)

@app.route("/api/admin/data")
@admin_required
def api_admin_data():
    c = db()
    users_raw = [dict(r) for r in c.execute("SELECT * FROM users").fetchall()]
    logs = [dict(r) for r in c.execute(
        "SELECT * FROM logs ORDER BY ts DESC LIMIT 200").fetchall()]
    c.close()
    for l in logs:
        try: l["response"] = json.loads(l["response"]) if l["response"] else {}
        except: l["response"] = {}
    users = [normalize_user(u) for u in users_raw]
    t = today_key()
    def day(ts): return dt.datetime.utcfromtimestamp(ts/1000).strftime("%Y-%m-%d")
    likes_today = sum(1 for l in logs if l["success"] and day(l["ts"])==t)
    auto_today = sum(1 for l in logs if l["type"]=="auto" and day(l["ts"])==t)
    failed = sum(1 for l in logs if not l["success"] and day(l["ts"])==t)
    c = db()
    ts_total = c.execute("SELECT COUNT(*) c FROM logs WHERE success=1").fetchone()["c"]
    tot_logs = c.execute("SELECT COUNT(*) c FROM logs").fetchone()["c"]
    c.close()
    return jsonify(ok=True, settings=get_settings(),
        users=[public_user(u) for u in users], logs=logs,
        stats={"totalUsers": len(users), "bannedUsers": sum(1 for u in users if u["banned"]),
               "autoUsers": sum(1 for u in users if u["auto_like"]),
               "likesToday": likes_today, "likesAllTime": ts_total,
               "autoToday": auto_today, "failedToday": failed,
               "successRate": round((ts_total/tot_logs)*100) if tot_logs else 100})

@app.route("/api/admin/data", methods=["POST"])
@admin_required
def api_admin_save():
    save_settings(request.get_json(silent=True) or {})
    return jsonify(ok=True)

@app.route("/api/admin/user/create", methods=["POST"])
@admin_required
def api_admin_create_user():
    b = request.get_json(silent=True) or {}
    u = (b.get("username") or "").strip(); p = b.get("password") or ""
    uid = str(b.get("uid") or "").strip(); region = (b.get("region") or "ind").strip()
    limit = int(b.get("dailyLimit") or 5); auto = bool(b.get("autoLike"))
    if not (u and p and uid): return jsonify(ok=False, error="All fields required."), 400
    if len(u) < 3: return jsonify(ok=False, error="Username min 3 chars."), 400
    if len(p) < 6: return jsonify(ok=False, error="Password min 6 chars."), 400
    if not re.fullmatch(r"\d{6,15}", uid): return jsonify(ok=False, error="UID 6-15 digits."), 400
    c = db()
    if c.execute("SELECT 1 FROM users WHERE LOWER(username)=LOWER(?)", (u,)).fetchone():
        c.close(); return jsonify(ok=False, error="Username taken."), 409
    if c.execute("SELECT 1 FROM users WHERE uid=?", (uid,)).fetchone():
        c.close(); return jsonify(ok=False, error="UID already registered."), 409
    user_id = str(uuid.uuid4())
    c.execute("INSERT INTO users(id,username,uid,region,password_hash,daily_limit,"
              "used_today,auto_used_today,last_reset_date,last_like_at,auto_like,banned,"
              "total_likes,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
              (user_id, u, uid, region, hash_pw(p), max(0,limit), 0, 0, today_key(), 0,
               1 if auto else 0, 0, 0, int(time.time()*1000)))
    c.commit()
    row = c.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    c.close()
    return jsonify(ok=True, user=public_user(normalize_user(row)))

@app.route("/api/admin/user", methods=["POST"])
@admin_required
def api_admin_update_user():
    b = request.get_json(silent=True) or {}
    uid = b.get("id")
    if not uid: return jsonify(ok=False, error="Missing id"), 400
    c = db()
    if not c.execute("SELECT 1 FROM users WHERE id=?", (uid,)).fetchone():
        c.close(); return jsonify(ok=False, error="Not found"), 404
    updates, params = [], []
    if "banned" in b: updates.append("banned=?"); params.append(1 if b["banned"] else 0)
    if "autoLike" in b: updates.append("auto_like=?"); params.append(1 if b["autoLike"] else 0)
    if "dailyLimit" in b: updates.append("daily_limit=?"); params.append(max(0, int(b["dailyLimit"] or 0)))
    if b.get("region"): updates.append("region=?"); params.append(str(b["region"]))
    if b.get("uid") and re.fullmatch(r"\d{6,15}", str(b["uid"])):
        updates.append("uid=?"); params.append(str(b["uid"]))
    if b.get("password"):
        if len(str(b["password"])) < 6:
            c.close(); return jsonify(ok=False, error="Password min 6."), 400
        updates.append("password_hash=?"); params.append(hash_pw(str(b["password"])))
    if b.get("resetToday"):
        updates.append("used_today=0"); updates.append("auto_used_today=0")
        updates.append("last_reset_date=?"); params.append(today_key())
    if updates:
        params.append(uid)
        c.execute(f"UPDATE users SET {', '.join(updates)} WHERE id=?", params)
        c.commit()
    c.close()
    return jsonify(ok=True)

@app.route("/api/admin/user", methods=["DELETE"])
@admin_required
def api_admin_delete_user():
    uid = request.args.get("id")
    if not uid: return jsonify(ok=False, error="Missing id"), 400
    c = db(); c.execute("DELETE FROM users WHERE id=?", (uid,)); c.commit(); c.close()
    return jsonify(ok=True)

@app.route("/api/cron/auto-like", methods=["GET", "POST"])
def api_cron():
    if not session.get("admin"):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "): return jsonify(ok=False, error="Unauthorized"), 401
    return jsonify(run_autolike())

# ============================================================
# MAIN
# ============================================================
init_db()
start_scheduler()

if __name__ == "__main__":
    print("=" * 60)
    print(" Zesty Likes — running")
    print("=" * 60)
    print(f" Landing:      http://localhost:{PORT}/")
    print(f" User login:   http://localhost:{PORT}/login")
    print(f" Admin:        http://localhost:{PORT}/zestyadmin")
    print(f" Auto logs:    http://localhost:{PORT}/auto_logs_all_users")
    print(f" Admin creds:  {ADMIN_USERNAME} / {ADMIN_PASSWORD}")
    print("=" * 60)
    app.run(host="0.0.0.0", port=PORT, debug=False, threaded=True)
