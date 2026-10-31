import os, sqlite3, secrets, time, hmac, hashlib, base64, json
from flask import Flask, request, render_template_string, make_response
from markupsafe import escape

app = Flask(__name__)
DB = "ctf.db"
FLAGS = {"c1": os.environ.get("FLAG_C1", "FLAG{sqli_login_bypass_7f2a}"),
         "c2": os.environ.get("FLAG_C2", "FLAG{reflected_xss_cookie_91c4}"),
         "c3": os.environ.get("FLAG_C3", "FLAG{idor_invoice_c7d9}"),
         "c4": os.environ.get("FLAG_C4", "FLAG{jwt_alg_none_e41b}")}
CHALLENGES = [("c1", "SQL Injection: login bypass", "/c1/login"),
              ("c2", "Reflected XSS: steal the cookie", "/c2/search"),
              ("c3", "IDOR: read another user's invoice", "/c3/invoices"),
              ("c4", "JWT: become admin", "/c4/login")]

PAGE = """<!doctype html><meta name=viewport content="width=device-width,initial-scale=1"><title>CTF Lab</title>
<style>body{font-family:system-ui;max-width:640px;margin:20px auto;padding:0 14px;background:#0f1420;color:#e6e9f2;line-height:1.5}
input,button{font:inherit;padding:9px;margin:4px 0;border-radius:6px;border:1px solid #33405f;background:#1b2236;color:#e6e9f2}
button{background:#4a6cf7;border:0;font-weight:600}a{color:#8fb0ff}pre{background:#1b2236;padding:10px;border-radius:6px;overflow-x:auto;white-space:pre-wrap}
.ok{color:#4cd39b}.bad{color:#ff6b78}</style>
<h1>{{ title }}</h1>
{% if kind == 'home' %}
  <p>Local CTF lab. Solve the challenges, then submit the flag.</p>
  <ul>{% for cid, name, url in challenges %}
    <li><a href="{{ url }}">{{ name }}</a> {% if cid in solved %}<span class="ok">solved</span>{% endif %}</li>
  {% endfor %}</ul>
  <form method="post" action="/submit"><input name="flag" placeholder="FLAG{...}" autocomplete="off"><button>Submit flag</button></form>
  {% if msg %}<p class="{{ cls }}">{{ msg }}</p>{% endif %}
{% else %}
  <p>Goal: log in as <b>admin</b> without knowing the password.</p>
  <form method="post"><input name="username" placeholder="Username"><br>
  <input name="password" placeholder="Password"><br><button>Login</button></form>
  {% if query %}<p>Executed query:</p><pre>{{ query }}</pre>{% endif %}
  {% if err %}<p class="bad">SQL error: {{ err }}</p>{% endif %}
  {% if msg %}<p class="ok">{{ msg }}</p>{% endif %}
  <p><a href="/">Back to scoreboard</a> | <a href="{{ other }}">{{ other_name }}</a></p>
{% endif %}"""

def conn():
    return sqlite3.connect(DB)

def init():
    c = conn()
    c.executescript("""DROP TABLE IF EXISTS users;
        CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT, password TEXT);
        CREATE TABLE IF NOT EXISTS solves(challenge TEXT PRIMARY KEY, ts INTEGER);""")
    c.execute("INSERT INTO users(username, password) VALUES('admin', ?)", (secrets.token_hex(16),))
    c.execute("INSERT INTO users(username, password) VALUES('guest', 'guest123')")
    c.commit(); c.close()

def solved_set():
    c = conn()
    s = {r[0] for r in c.execute("SELECT challenge FROM solves")}
    c.close()
    return s

def home(msg="", cls=""):
    return render_template_string(PAGE, kind="home", title="CTF Lab", challenges=CHALLENGES,
                                  solved=solved_set(), msg=msg, cls=cls)

@app.route("/")
def index():
    return home()

@app.route("/submit", methods=["POST"])
def submit():
    f = request.form.get("flag", "").strip()
    for cid, real in FLAGS.items():
        if secrets.compare_digest(f, real):
            c = conn()
            c.execute("INSERT OR IGNORE INTO solves VALUES(?, ?)", (cid, int(time.time())))
            c.commit(); c.close()
            return home("Correct! Challenge solved.", "ok")
    return home("Wrong flag.", "bad")

def login_page(vulnerable):
    query = err = msg = None
    if request.method == "POST":
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        c = conn()
        try:
            if vulnerable:
                query = f"SELECT id, username FROM users WHERE username='{u}' AND password='{p}'"
                row = c.execute(query).fetchone()           # VULNERABLE: string concatenation
            else:
                query = "SELECT id, username FROM users WHERE username=? AND password=?"
                row = c.execute(query, (u, p)).fetchone()   # FIXED: parameterized query
            if row:
                msg = "Welcome, " + row[1] + "!"
                if row[1] == "admin" and vulnerable:
                    msg += " Flag: " + FLAGS["c1"]
            else:
                msg = None; err = "Invalid credentials" if not vulnerable else None
                if vulnerable: msg = "Login failed."
        except Exception as e:
            err = str(e)
        c.close()
    other, other_name = ("/c1/fixed", "Fixed version") if vulnerable else ("/c1/login", "Vulnerable version")
    return render_template_string(PAGE, kind="login", title="Challenge 1: " + ("vulnerable" if vulnerable else "fixed"),
                                  query=query, err=err, msg=msg, other=other, other_name=other_name)

@app.route("/c1/login", methods=["GET", "POST"])
def c1_vuln():
    return login_page(True)

@app.route("/c1/fixed", methods=["GET", "POST"])
def c1_fixed():
    return login_page(False)


STYLE = "font-family:system-ui;max-width:640px;margin:20px auto;padding:0 14px"

def c2_page(q, safe):
    q = escape(q) if safe else q            # VULNERABLE when not escaped
    return ("<!doctype html><title>Search</title><body style='" + STYLE + "'>"
            "<h2>Challenge 2: reflected XSS</h2>"
            "<p>Goal: make your JavaScript run and read the cookie.</p>"
            "<form><input name=q placeholder='search'> <button>Search</button></form>"
            "<p>Results for: " + str(q) + "</p>"
            "<p><a href='" + ("/c2/search" if safe else "/c2/fixed") + "'>"
            + ("Vulnerable version" if safe else "Fixed version") + "</a> | <a href='/'>Scoreboard</a></p>")

@app.route("/c2/search")
def c2_vuln():
    resp = make_response(c2_page(request.args.get("q", ""), False))
    resp.set_cookie("c2_flag", FLAGS["c2"])          # readable by JavaScript (no HttpOnly)
    return resp

@app.route("/c2/fixed")
def c2_fixed():
    resp = make_response(c2_page(request.args.get("q", ""), True))
    resp.set_cookie("c2_flag", FLAGS["c2"], httponly=True, samesite="Strict")
    resp.headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'"
    return resp


C3_USER = "guest"
INVOICES = {
    1: {"owner": "admin", "item": "Server hosting", "amount": "4,200", "note": FLAGS["c3"]},
    2: {"owner": "bob", "item": "Laptop repair", "amount": "150", "note": "Paid"},
    3: {"owner": "guest", "item": "T-shirt", "amount": "20", "note": "Thanks for shopping!"},
}

def c3_page(title, body, other, other_name):
    return ("<!doctype html><title>Invoices</title><body style='" + STYLE + "'><h2>" + title + "</h2>" + body
            + "<p><a href='" + other + "'>" + other_name + "</a> | <a href='/'>Scoreboard</a></p>")

def invoice_html(iid):
    inv = INVOICES[iid]
    return ("<ul><li>Invoice #%d</li><li>Owner: %s</li><li>Item: %s</li><li>Amount: %s</li><li>Note: %s</li></ul>"
            % (iid, escape(inv["owner"]), escape(inv["item"]), escape(inv["amount"]), escape(inv["note"])))

@app.route("/c3/invoices")
def c3_list():
    body = ("<p>Logged in as <b>guest</b>.</p><p>Goal: read the <b>admin's</b> invoice without being admin.</p>"
            "<p>Your invoice: <a href='/c3/invoice/3'>Invoice #3</a></p>")
    return c3_page("Challenge 3: IDOR", body, "/c3/fixed/invoices", "Fixed version")

@app.route("/c3/invoice/<int:iid>")
def c3_vuln(iid):
    if iid not in INVOICES:
        return "Not found", 404
    return c3_page("Invoice", invoice_html(iid), "/c3/invoices", "Back")     # VULNERABLE: no owner check

@app.route("/c3/fixed/invoices")
def c3_fixed_list():
    body = "<p>Logged in as <b>guest</b>.</p><p>Your invoice: <a href='/c3/fixed/invoice/3'>Invoice #3</a></p>"
    return c3_page("Challenge 3: fixed", body, "/c3/invoices", "Vulnerable version")

@app.route("/c3/fixed/invoice/<int:iid>")
def c3_fixed(iid):
    inv = INVOICES.get(iid)
    if not inv or inv["owner"] != C3_USER:                                   # FIXED: ownership check
        return "Not found", 404
    return c3_page("Invoice", invoice_html(iid), "/c3/fixed/invoices", "Back")


SECRET = secrets.token_bytes(32)

def b64e(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def sign(msg):
    return b64e(hmac.new(SECRET, msg.encode(), hashlib.sha256).digest())

def make_token(sub, role):
    h = b64e(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    p = b64e(json.dumps({"sub": sub, "role": role, "exp": int(time.time()) + 3600}).encode())
    return h + "." + p + "." + sign(h + "." + p)

def verify(token, vulnerable):
    try:
        h, p, sg = token.split(".")
        header = json.loads(b64d(h))
        payload = json.loads(b64d(p))
    except Exception:
        return None
    if vulnerable and str(header.get("alg", "")).lower() == "none":
        return payload                                   # VULNERABLE: trusts the token's own alg claim
    if header.get("alg") != "HS256":
        return None
    if not hmac.compare_digest(sg.encode(), sign(h + "." + p).encode()):
        return None
    if payload.get("exp", 0) < time.time():
        return None
    return payload

def c4_page(title, body, other, other_name):
    return ("<!doctype html><title>JWT</title><body style='" + STYLE + "'><h2>" + title + "</h2>" + body
            + "<p><a href='" + other + "'>" + other_name + "</a> | <a href='/'>Scoreboard</a></p>")

def c4_login(vulnerable):
    token = make_token("guest", "guest")
    admin = "/c4/admin" if vulnerable else "/c4/fixed/admin"
    body = ("<p>Goal: reach the admin panel as <b>admin</b>.</p><p>Your guest token:</p>"
            "<pre style='white-space:pre-wrap;word-break:break-all'>" + token + "</pre>"
            "<p><a href='" + admin + "?token=" + token + "'>Open admin panel with this token</a></p>"
            "<p>Tip: the panel reads the token from the URL (<code>?token=...</code>).</p>")
    other, name = ("/c4/fixed/login", "Fixed version") if vulnerable else ("/c4/login", "Vulnerable version")
    return c4_page("Challenge 4: JWT" + ("" if vulnerable else " (fixed)"), body, other, name)

def c4_admin(vulnerable):
    payload = verify(request.args.get("token", ""), vulnerable)
    other, name = ("/c4/login", "Back") if vulnerable else ("/c4/fixed/login", "Back")
    if not payload:
        return c4_page("Admin panel", "<p>Invalid token.</p>", other, name), 401
    role = str(payload.get("role", ""))
    if role == "admin":
        extra = ("<p>Flag: " + FLAGS["c4"] + "</p>") if vulnerable else "<p>Genuine admin tokens only.</p>"
        return c4_page("Admin panel", "<p>Welcome, admin!</p>" + extra, other, name)
    return c4_page("Admin panel", "<p>Access denied. Your role: <b>" + str(escape(role)) + "</b></p>", other, name), 403

@app.route("/c4/login")
def c4_l():
    return c4_login(True)

@app.route("/c4/admin")
def c4_a():
    return c4_admin(True)

@app.route("/c4/fixed/login")
def c4_fl():
    return c4_login(False)

@app.route("/c4/fixed/admin")
def c4_fa():
    return c4_admin(False)

init()
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5100)
