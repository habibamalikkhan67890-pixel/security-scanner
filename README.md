# Security Scanner - FastAPI backend + Next.js (TypeScript) frontend

Educational web-application security scanner. It checks a website **you own or are authorized to test**, stores results in
SQLite and shows them in a responsive dashboard with severity, evidence, OWASP Top 10 mapping and remediation advice.

> **Responsible use.** Scan only systems you own or have written permission to test. A scan with few findings does **not**
> prove a site is secure - this tool is limited and non-destructive by design.

```
security_scanner/
|-- backend/     FastAPI + SQLite + Requests/BeautifulSoup (+ optional OWASP ZAP)   -> http://127.0.0.1:5000/api
`-- frontend/    Next.js 16 + React 19 + TypeScript (strict)                        -> http://localhost:3000
```

The browser only talks to Next.js. Next.js forwards `/api/*` to FastAPI (`frontend/next.config.ts`), so the session cookie
and CSRF token stay same-origin and no CORS setup is needed.

## 1. Quick start (Windows PowerShell)

Needs **Python 3.10+** and **Node.js 20.9+**. Two terminals.

**Terminal 1 - backend** (pick pip *or* uv):
```powershell
cd backend
# --- pip ---
python -m venv .venv ; .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
# --- or uv ---
uv venv ; uv pip install -r requirements.txt ; uv run python app.py
```
First time: `Copy-Item .env.example .env`, then put a long random value after `SECRET_KEY=`
(`python -c "import secrets; print(secrets.token_hex(32))"`). Without it a random key is used and sessions reset on restart.
If `Activate.ps1` is blocked: `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`.

**Terminal 2 - frontend:**
```powershell
cd frontend
npm install
Copy-Item .env.example .env.local     # BACKEND_URL=http://127.0.0.1:5000
npm run dev
```
Open <http://localhost:3000>. API docs (Swagger UI): <http://127.0.0.1:5000/api/docs>.
Production build: `npm run build ; npm start` (`BACKEND_URL` is read at build time - rebuild if you change it).

### Practice target (lab mode)
Local addresses are blocked by default (SSRF protection). To practise on the bundled misconfigured site:
```powershell
# backend/.env:  ALLOW_LAB_TARGETS=true   (restart the backend; lab mode allows any port)
cd backend
python lab_server.py --profile vulnerable --port 5001     # third terminal
```
Scan `http://127.0.0.1:5001/`. For **Compare**, also run `--profile hardened --port 5002`, scan it, then compare both scans.
The lab only serves fake static content. Turn lab mode off again after practising.

## 2. What it checks

| Area | Checks |
|---|---|
| HTTPS / TLS | HTTPS availability, HTTP->HTTPS redirect, certificate validity/expiry, TLS version, legacy TLS 1.0/1.1 probe |
| Headers | CSP, HSTS, clickjacking protection, `nosniff`, Referrer-Policy, Permissions-Policy, CORS misconfiguration |
| Cookies | `HttpOnly`, `Secure`, `SameSite`, `__Host-`/`__Secure-` rules (values are never stored) |
| Disclosure | `Server`, `X-Powered-By`, generator meta tag, verbose errors |
| Exposed files | 18 well-known paths with **content signatures** (no "200 = exposed" guesses), directory listing |
| Forms | Password over HTTP/GET, cross-origin password forms, missing CSRF-token indicator, mixed content, missing SRI |
| HTTP methods | `Allow` header, `TRACE` |
| OWASP ZAP | Optional passive scan, or authorized active scan, through ZAP's REST API |

Every finding has a **severity** (Critical/High/Medium/Low/Informational) and a **status**: `confirmed` (observed directly),
`potential` (needs manual verification) or `not_completed` (could not run - never counted as a vulnerability).

| Severity | Rule |
|---|---|
| Critical | Reserved - built-in checks never exploit anything, so they never assign it |
| High | Confirmed exposure of credentials/sensitive data: no HTTPS, password form over HTTP/GET, invalid certificate, exposed `.env`/`.git`/backup |
| Medium | Missing/weak defensive controls: no CSP/HSTS/clickjacking protection, directory listing, TRACE, weak session cookie, legacy TLS |
| Low | Hardening gaps: version banners, missing `nosniff`/Referrer-Policy, missing SRI |
| Informational | Context: TLS summary, form inventory, scope notes |

OWASP mapping uses Top 10:2025. ZAP alerts keep the tag ZAP provides (may reference 2021).

## 3. API (all under `/api`, JSON `{"ok": ..., "error": ...}`)

| Method | Path | Purpose |
|---|---|---|
| GET | `/health`, `/csrf`, `/config`, `/dashboard`, `/scans`, `/zap/status` | status, CSRF token, limits, stats, history |
| GET | `/scan/{id}`, `/compare?a=&b=` | scan (+findings when finished), compare two scans |
| GET | `/scan/{id}/export.json` / `export.csv` | report download |
| POST | `/scan`, `/scan/{id}/delete`, `/history/delete-all` | **need** header `X-CSRF-Token` (from `/csrf`) |

## 4. How it protects itself

* **SSRF:** only `http(s)`, no credentials/ambiguous numeric IPs; every resolved address must be public (private, loopback, link-local, reserved, IPv6-wrapped IPv4 and cloud-metadata ranges are blocked); ports limited to `ALLOWED_PORTS`.
* **Redirects / DNS rebinding:** redirects are followed manually and re-validated per hop; the IP is checked again at socket-connect time. System proxy variables are ignored.
* **Limits:** request timeouts, response size cap, request budget + delay per scan, hard scan deadline, concurrent-scan limit with bounded queue, rate limit on `POST /scan`.
* **API:** CSRF token on every POST (signed session cookie `scanner_session`, `HttpOnly`, `SameSite=Lax`, `Secure` via `COOKIE_SECURE=true`), Host-header allow-list, 16 KB body limit, strict `default-src 'none'` CSP, `nosniff`, `X-Frame-Options`, parameterized SQL, CSV formula-injection neutralisation, no stack traces to clients.
* **Never done:** exploitation, brute force, DoS. The built-in scanner sends only `GET`, `OPTIONS` and `TRACE`.

## 5. OWASP ZAP (optional)

Install ZAP from <https://www.zaproxy.org/download/>, then start it in daemon mode:
```powershell
cd "C:\Program Files\ZAP\Zed Attack Proxy"
.\zap.bat -daemon -host 127.0.0.1 -port 8090 -config api.key=YOUR_ZAP_KEY
```
In `backend/.env` set `ZAP_URL=http://127.0.0.1:8090` and `ZAP_API_KEY=YOUR_ZAP_KEY`, restart the backend. The Scanner page shows
whether ZAP is connected. **Passive** mode (default) = limited spider + passive scanner. **Active** mode needs
`ZAP_ACTIVE_ENABLED=true` *and* a second confirmation checkbox. If ZAP is down the scan still completes with the Python checks and
the report shows a clearly labelled "not completed" item - no simulated ZAP results are ever created.

## 6. Tests

```powershell
cd backend ; pip install -r requirements-dev.txt ; pytest -q      # 212 tests (lab servers + mock ZAP, no internet)
cd frontend ; npm run typecheck ; npm test                         # TypeScript + 40 Vitest tests
```
| Required case | Test |
|---|---|
| Valid/invalid URLs | `test_security.py`, `test_api.py::test_invalid_urls_rejected` |
| HTTP/HTTPS sites, headers, cookies | `test_scanner.py`, `test_tls.py` |
| Redirects to prohibited IPs | `test_http_client.py`, `test_scan_service.py` |
| Database + history | `test_database.py`, `test_api.py::test_full_scan_flow_with_exports_and_delete` |
| ZAP unavailable | `test_zap.py`, `test_scan_service.py`, `test_api.py::test_zap_status_endpoint_when_unavailable` |
| Failures/timeouts | `test_http_client.py`, `test_scanner.py`, `test_scan_service.py` |
| Export, CSRF, rate limit | `test_api.py` |

## 7. Honest limitations

* OWASP ZAP is external software; the integration is tested against a **mock** of its documented API, not every real ZAP version. ZAP makes its own network requests, so keep it on a trusted machine.
* Not implemented (reported as `not_completed`): SQL injection/XSS testing, authentication/access-control and business-logic testing, JavaScript-rendered content, crawling, CVE detection.
* Single-user local tool, no accounts - do not expose it to the internet. Behind the Next.js proxy every browser appears as `127.0.0.1` and `X-Forwarded-For` is deliberately **not** trusted (it can be spoofed), so `RATE_LIMIT_PER_MINUTE` is one shared limit.
* Dashboard totals include every saved scan; the rate limiter is in memory (one process).

## 8. Troubleshooting

| Problem | Fix |
|---|---|
| UI says "Cannot reach the scanner backend" | Start the backend (`python app.py` in `backend/`), check `BACKEND_URL` and rebuild/restart Next.js |
| "Security token missing or invalid" | Reload the page (the session cookie expired or `SECRET_KEY` changed) |
| "blocked by SSRF protection" for localhost | Intended. Set `ALLOW_LAB_TARGETS=true` only for lab practice |
| "Invalid Host header" | Add the host name you use to `ALLOWED_HOSTS` |
| "Port 3000 is not allowed" | Public targets are limited to `ALLOWED_PORTS`; lab mode allows any port |
| ZAP "Cannot connect" / "rejected the API key" | Start ZAP with `-daemon`; `ZAP_URL` and `ZAP_API_KEY` must match |
| "Request limit reached" / time limit | Raise `MAX_REQUESTS_PER_SCAN` / `SCAN_TIMEOUT` |
| `Address already in use` | Change `API_PORT` (and `BACKEND_URL` in `frontend/.env.local`) |
