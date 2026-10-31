# CTF Lab

**Live demo:** https://ctf-lab-x87i.onrender.com/c1/login (SQLi, XSS, IDOR challenges; JWT challenge is local-only, see below)

A small local CTF: 4 classic web vulnerabilities, each with a vulnerable version and a fixed version side by side.

> Educational project. Runs locally only (`127.0.0.1`). Fake data, fake "admin" account, nothing real.

## Challenges

### 1. SQL Injection: login bypass
- **Bug:** the login query is built with string concatenation (`f"...WHERE username='{u}'..."`), so user input becomes part of the SQL.
- **Exploit:** `username = admin' -- ` makes everything after `--` a comment, dropping the password check.
- **Fix:** parameterized query (`?` placeholders). User input is always treated as data, never as code.

### 2. Reflected XSS
- **Bug:** the search query is reflected into the page unescaped, and the flag cookie has no `HttpOnly`.
- **Exploit:** `<script>alert(document.cookie)</script>` runs in the browser and reads the cookie.
- **Fix:** output escaping (so `<` becomes `&lt;`), `HttpOnly` + `SameSite=Strict` on the cookie, and a Content-Security-Policy header.

### 3. IDOR: read another user's invoice
- **Bug:** `/c3/invoice/<id>` returns any invoice by ID with no ownership check.
- **Exploit:** change the ID in the URL from your own invoice to someone else's (e.g. `3` -> `1`).
- **Fix:** check `invoice.owner == current_user` on every request, and return 404 (not 403) so an attacker can't tell which IDs exist.

### 4. JWT: `alg: none` forgery
- **Bug:** the server trusts the `alg` field inside the token itself, so a token claiming `"alg": "none"` skips signature verification.
- **Exploit:** craft a token with header `{"alg":"none",...}`, payload `{"role":"admin",...}`, and an empty signature.
- **Fix:** the server fixes the expected algorithm itself (never reads it from the token), rejects `alg: none`, and still checks `exp`.

## What I'd do differently in a real app
- Never store secrets in app code reachable by users; use environment variables (done here for flags via `FLAG_C1..C4`).
- Log and rate-limit login attempts (SQLi and brute force both show up as repeated failed logins).
- Prefer an allowlist of expected JWT algorithms over trusting the token.

## Run it
    pip install -r requirements.txt
    python app.py   # http://127.0.0.1:5100
