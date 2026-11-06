# CLAUDE.md — OSINT / Cyber Intelligence Investigation Platform

> Permanent project context, architecture reference, and AI session continuity memory.
> Update this file whenever architecture, features, or engineering rules change.
>
> **Phase 1 (Environment Stabilization) — COMPLETE as of 2026-05-10**
> **Phase 2 (Runtime Stabilization & Frontend Consistency) — COMPLETE as of 2026-05-10**
> **Phase 3 (Frontend Overhaul & Feature Additions) — COMPLETE as of 2026-05-11**
> **Phase 4 (PDF Reports, Master Prompt, Branding & Path Fix) — COMPLETE as of 2026-05-11**
> **Phase 5 (Auth Overhaul, Admin Panel Polish & Dashboard UI Enhancements) — COMPLETE as of 2026-05-12**
> **Phase 6 (Subprocess Isolation, SSE Hardening & user-scanner Fix) — COMPLETE as of 2026-05-12**
> **Phase 7 (Dashboard Tool Selection UX — Default All Selected) — COMPLETE as of 2026-05-12**

---

## Project Overview

**Name:** Repo of OSINT/SOCMINT — Cyber Intelligence Investigation Platform  
**Client:** Hyderabad City Police (Telangana State Police)  
**Purpose:** Law-enforcement OSINT platform for structured intelligence gathering on email addresses, usernames, phone numbers, and images. Restricted to authorized police personnel via username + password login.  
**Status:** Active production use. Python 3.11 + Flask, running on Windows 11.

**Application Root:** `osint_final_project/Sam/`  
**Start Command:** `python start_server.py` (from within `osint_final_project/Sam/`) — or `python Sam/start_server.py` from the repo root  
**Port:** 8000  
**Auth:** Username + password (no email domain restriction). Default admin: `admin` / `POLICE_PORTAL_PASSWORD` env var (defaults to `ChangeMe@123`).

---

## Directory Structure

```
osint_final_project/                     ← Git repository root (.git here)
├── Sam/                                 ← APPLICATION ROOT (all dev happens here)
│   ├── .venv/                           ← CANONICAL Python 3.11 venv (Phase 1 created) ✅
│   ├── app.py                           ← Monolithic Flask core (~1,700+ lines)
│   ├── start_server.py                  ← Dev startup script (portable — Phase 1 fixed) ✅
│   ├── requirements.txt                 ← Pinned dependencies (Phase 1 created) ✅
│   ├── .env.example                     ← Environment variable template (Phase 1 created) ✅
│   ├── templates/                       ← All Jinja2 HTML templates
│   │   ├── base.html                    ← Master layout (navbar, header, CSS vars) ✅ Phase 3/4
│   │   ├── index.html                   ← Main dashboard (multi-tool scan page) ✅ Phase 3/4/7
│   │   ├── login.html                   ← Login page (standalone, no base.html) ✅ Phase 3
│   │   ├── email_tools.html             ← Email intelligence page
│   │   ├── phone_tools.html             ← Phone intelligence page
│   │   ├── username_tools.html          ← Username intelligence (extends base.html) ✅ Phase 2
│   │   ├── image_intel.html             ← Image metadata / EXIF analysis page ✅ Phase 3/4
│   │   ├── other_links.html             ← Merged OSINT + commercial links directory ✅ Phase 3
│   │   ├── ask_ai.html                  ← AI investigation copilot (OpenAI GPT-4o-mini) ✅ Phase 3/4
│   │   ├── master_prompt.html           ← Master investigation prompt reference page ✅ Phase 4
│   │   ├── admin_users.html             ← Admin user management page
│   │   └── [REMOVED] osint_links.html / commercial_links.html / ai_assistant.html
│   ├── routes/
│   │   └── image_routes.py              ← Flask Blueprint for /image-intel/* endpoints ✅ Phase 4
│   ├── services/
│   │   ├── __init__.py
│   │   ├── user_scanner_service.py      ← user-scanner CLI wrapper + SSE streaming
│   │   ├── image_metadata_service.py    ← PIL/Pillow EXIF metadata extractor
│   │   └── pdf_report_service.py        ← Shared PDF report generator (fpdf2) ✅ Phase 4
│   ├── Sam/                             ← Embedded Holehe library (123 modules)
│   │   ├── __init__.py
│   │   ├── core.py                      ← Holehe async engine (trio + httpx)
│   │   ├── instruments.py
│   │   ├── localuseragent.py
│   │   └── modules/                     ← 15 categories: cms, crm, forum, social_media, etc.
│   ├── data/
│   │   ├── police_users.json            ← User accounts (scrypt-hashed passwords)
│   │   ├── other_links.json             ← Admin-managed links — 21 tools, 8 categories ✅ Phase 3/4
│   │   └── [REMOVED] osint_links.json / commercial_links.json
│   ├── audit_logs/
│   │   └── police_portal_audit.jsonl    ← Append-only audit trail (every action logged)
│   └── reports/                         ← Reserved for future report storage

# Root-level workspace (c:\Users\Zayed Ali\Downloads\osint_final_project\)
├── audit_logs/                          ← Duplicate audit_logs at root — NOT used by app
└── reports/                             ← Duplicate reports at root — NOT used by app
```

---

## Python Environment

**Canonical `.venv` (use this — Phase 1 created):**  
`osint_final_project/Sam/.venv/Scripts/python.exe` (Python 3.11.9)

Activate: `.venv\Scripts\activate` (Windows) or `.venv/bin/activate` (bash)  
Install: `pip install -r requirements.txt`  
Sam package installed editable: `pip install -e .` (allows `import Sam.core` from anywhere)

**Fallback system Python (if venv unavailable):**  
`C:\Users\Zayed Ali\AppData\Local\Programs\Python\Python311\python.exe`

**All required packages in the canonical .venv:**

| Package | Version | Purpose |
|---------|---------|---------|
| flask | 3.1.2 | Web framework |
| werkzeug | 3.1.3 | WSGI + password hashing |
| trio | 0.33.0 | Async runtime for Holehe |
| httpx | 0.28.1 | Async HTTP client (also used for OpenAI API calls) |
| phonenumbers | 9.0.30 | Phone metadata parsing |
| Pillow | 11.3.0 | Image EXIF extraction |
| fpdf2 | 2.8.7 | PDF report generation |
| sherlock-project | 0.16.0 | Username OSINT (subprocess) |
| maigret | 0.6.0 | Username OSINT (subprocess) |
| user-scanner | 1.3.6 | Email/username OSINT (subprocess) |
| holehe | 1.61 | Email footprint (embedded library) |
| beautifulsoup4 | 4.14.3 | HTML parsing for Holehe |
| termcolor | 3.3.0 | Terminal color (Holehe dep) |

---

## Architecture Summary

```
Browser
  │
  ├── GET/POST /              → index.html      (multi-tool main dashboard)
  ├── GET/POST /tools/email   → email_tools.html
  ├── GET/POST /tools/phone   → phone_tools.html
  ├── GET/POST /tools/username → username_tools.html
  ├── GET /image-intel/       → image_intel.html (Blueprint: image_routes.py)
  ├── GET /login              → login.html
  ├── GET /admin/users        → admin_users.html (admin only)
  ├── GET/POST /other-links   → other_links.html (merged OSINT + commercial links)
  ├── GET /web-links          → 302 redirect → /other-links
  ├── GET /commercial-links   → 302 redirect → /other-links
  ├── GET /ask-ai             → ask_ai.html (AI investigation copilot)
  ├── POST /api/ask-ai        → OpenAI GPT-4o-mini → JSON response
  ├── GET /master-prompt      → master_prompt.html (static reference page)
  │
  ├── SSE /api/stream/scan       → user_scanner_service.scan_streaming()
  ├── SSE /api/stream/sherlock   → subprocess: python -m sherlock [username]
  ├── SSE /api/stream/maigret    → subprocess: python -m maigret [username]
  │
  ├── POST /image-intel/upload   → validate + save to temp dir
  ├── POST /image-intel/analyze  → PIL EXIF extraction → JSON
  │
  ├── GET /download/json         → session payload → JSON download
  ├── GET /download/csv          → session payload → CSV download
  ├── POST /api/export/dashboard-pdf → browser-POSTed _pdfData → PDF (fpdf2) ✅ Phase 4
  ├── GET /infra-intel/download/pdf  → session['last_infra_scan'] → PDF ✅ Phase 4
  ├── GET /image-intel/download/pdf  → session['last_image_analysis'] → PDF ✅ Phase 4
  └── GET /ask-ai/download/pdf       → session['last_ask_ai'] → PDF ✅ Phase 4

Backend Tool Runners (all in app.py):
  run_holehe()             → trio.run() → httpx async → 123 modules → structured list
  run_gravatar_check()     → httpx.get() → MD5 hash check
  run_domain_intelligence() → socket + nslookup subprocess
  run_username_footprint() → httpx.Client, 11 manual platforms
  run_disposable_check()   → static set membership check
  run_mx_security_check()  → nslookup subprocess (SPF/DMARC TXT records)
  run_phone_intelligence() → phonenumbers library → structured dict
  run_sherlock_scan()      → subprocess.run() → regex URL extraction (BLOCKING version)
  run_maigret_scan()       → subprocess.run() → regex URL extraction (BLOCKING version)
  run_domain_whois_recon() → whois + nslookup subprocess
  run_email_pivots()       → static pivot link generation (HIBP, DeHashed, IntelX, Google, Bing)
  /api/ask-ai              → httpx.post() → OpenAI Chat Completions → JSON structured response
```

### Data Flow: Synchronous Tools
```
POST /tools/email (email=...) 
  → run_holehe(email) → trio async → 123 checks → filtered results
  → run_disposable_check(email) → dict
  → run_email_pivots(email) → pivot links
  → render_template(email_tools.html, results=...) → structured HTML table
```

### Data Flow: Streaming Tools (SSE)
```
POST / (username=..., tools=[sherlock])
  → Flask renders page with Sherlock section placeholders
  → Browser JS: new EventSource('/api/stream/sherlock?username=...')
  → Flask: stream_sherlock() generator → subprocess.Popen(sherlock)
  → Line-by-line: extract URLs → yield JSON events to browser
  → Browser: appends rows to live table, animates progress bar
  → On complete: shows summary badge, closes EventSource
```

### Data Flow: Main Dashboard PDF (Phase 4)
```
Browser accumulates results in _pdfData JS object as SSE/AJAX events arrive:
  Holehe SSE result    → _pdfData.holehe.push(r)
  Sherlock SSE result  → _pdfData.sherlock_profiles.push(url)
  Maigret SSE result   → _pdfData.maigret_profiles.push(url)
  Userdeep SSE result  → _pdfData.userdeep_profiles.push(url)  [deduped]
  User-Scanner found   → _pdfData.user_scanner_email/username.push({platform,url,category,status})
  Disposable AJAX      → _pdfData.disposable_result = d
  Phone AJAX           → _pdfData.phone_result = d
  Email pivots AJAX    → _pdfData.email_pivots_result = d

User clicks "Download PDF Report":
  → downloadDashboardPdf() POSTs _pdfData as JSON to /api/export/dashboard-pdf
  → Flask maps payload → generate_dashboard_pdf(payload) → PDF bytes
  → Browser receives blob → synthetic <a> click → file download
```

### Data Flow: Ask AI
```
GET /ask-ai → ask_ai.html (form UI)
POST /api/ask-ai (JSON: {query, context})
  → _is_authorized() check
  → httpx.post(openai_api, headers={Authorization: Bearer OPENAI_API_KEY})
  → response_format: {"type": "json_object"}
  → session['last_ask_ai'] = {'query': query, 'result': result}  ← stored for PDF
  → returns structured JSON {summary, findings[], recommendations[], caveats}
  → Browser renders sections as formatted cards
```

### Authentication Flow
```
POST /login (username=..., password=...)
  → _load_police_accounts() → username-keyed dict (migrates legacy email keys on load)
  → _verify_password(stored_hash, password) → bool
  → session["authorized"] = True
  → session["police_email"] = username   ← key name kept for session compatibility
  → session["police_role"] = admin | officer | analyst
  → _write_audit_log("login", "success", ...)
  → redirect to /

All routes: if not _is_authorized(): redirect to /login
Admin routes: if not _is_admin(): redirect to /
```

**Username rules:** max 20 chars, `[a-zA-Z0-9_.]` only, case-insensitive uniqueness (`_USERNAME_RE`).  
**Password rules:** min 8 chars, ≥1 uppercase, ≥1 digit, ≥1 special character (`_validate_password_strength()`).  
**Migration:** `_migrate_email_keys()` strips `@domain` from legacy JSON keys; runs in `_load_police_accounts()` and `admin_users()` route; saves permanently on first admin panel access.

---

## Current Modules / Features

### 1. Email Intelligence
- **Holehe Email Footprint** — 123-module async check across social, commerce, music, forums, etc. Shows only confirmed registrations.
- **Disposable Email Risk Check** — Static domain list check with risk level (High/Low)
- **Email Breach & Intel Pivots** — Links to HIBP, DeHashed, IntelX, Google Dork, Bing Dork
- **User-Scanner OSINT Engine** — 195+ platforms, live SSE streaming, categorized results with found/not-found status

### 2. Username Intelligence
- **User-Scanner OSINT Engine** — Same as above, username mode (`-u` flag)
- **Sherlock Username Deep Scan** — ~300 sites, real-time SSE streaming with progress bar
- **Maigret Username Deep Scan** — ~500 sites, real-time SSE streaming with progress bar
- **Username Deep Scan (Sherlock + Maigret)** — Combined dedup view from both tools simultaneously
- **Username Footprint Check** — Manual 11-platform HTTP check (GitHub, GitLab, Instagram, etc.)

### 3. Phone Intelligence
- **Phone Metadata** — E.164/international/national format, carrier, region, number type, timezone
- **Search Pivots** — Google, Bing, Truecaller, Sync.me links for the parsed number

### 4. Image Intelligence (`/image-intel/`)
- **Upload & Validate** — Magic byte MIME check, 50MB limit, UUID-renamed filenames
- **EXIF Metadata Extraction** — PIL/Pillow: camera make/model, timestamps, GPS coordinates
- **GPS to Google Maps** — Decimal degree conversion + Maps URL generation
- **Metadata Status** — Full / Partial / Stripped detection with forensic description
- **JSON Export** — Download analysis as structured JSON
- **PDF Export** — Download Image Intel report (`/image-intel/download/pdf`) ✅ Phase 4

### 5. Infrastructure Intel (`/infra-intel`)
- **Shodan-Powered Host Recon** — IP/domain lookup, open ports, services, technologies, SSL, CVEs
- **PDF Export** — Download Infra Intel report (`/infra-intel/download/pdf`); stored in `session['last_infra_scan']` ✅ Phase 4

### 6. Platform Links (`/other-links`) ✅ Phase 3/4
- **Merged OSINT + Commercial Links** — Unified at `/other-links` backed by `data/other_links.json`.
- **Pre-populated with 21 tools** across 8 categories (Username Intelligence, Email Intelligence, Infrastructure Intelligence, Threat Intelligence, Metadata Analysis, Malware Analysis, DFIR, Reconnaissance) ✅ Phase 4
- Legacy routes `/web-links` and `/commercial-links` redirect to `/other-links`.
- Admin can add/delete links from the UI.

### 7. Ask AI (`/ask-ai`) ✅ Phase 3/4
- **AI Investigation Copilot** — Live OpenAI GPT-4o-mini integration.
- Uses `httpx` (no `openai` package) to call OpenAI Chat Completions API with `response_format: {"type": "json_object"}`.
- Requires `OPENAI_API_KEY` environment variable; gracefully shows an error if unset.
- **PDF Export** — Download AI investigation report (`/ask-ai/download/pdf`); stored in `session['last_ask_ai']` ✅ Phase 4

### 8. Master Prompt (`/master-prompt`) ✅ Phase 4
- **Static reference page** — Displays the master investigation prompt verbatim in a styled monospace box.
- **Copy Prompt button** — `navigator.clipboard.writeText()` with `execCommand` fallback; shows "✓ Copied!" state for 2.5s.
- **6-step instruction cards** — Numbered guide for using the master prompt in investigations.
- Does NOT touch scan logic, auth, SSE, or any backend processing.

### 9. PDF Report Service (`services/pdf_report_service.py`) ✅ Phase 4
- **Single shared service** for all 4 PDF generators — no separate/inconsistent per-page PDF logic.
- **`generate_dashboard_pdf(payload)`** — email/username/phone intelligence: Holehe, User-Scanner (email+username), Sherlock, Maigret, Combined (userdeep), Phone, Disposable, Email Pivots. Sherlock/Maigret/userdeep tables include Platform, Username, Profile URL, Status columns.
- **`generate_infra_pdf(result, query)`** — host info, geo, open ports/services, technologies, SSL/TLS, CVEs.
- **`generate_image_pdf(metadata)`** — file info, device/camera, timestamps, GPS coordinates.
- **`generate_ask_ai_pdf(query, result)`** — investigation query, summary, recommended tools, investigation flow, legal notes.
- **Branding:** `HYDERABAD CITY POLICE` header on every page; khaki accent line; officer name + timestamp footer.
- **Cross-platform fonts:** only fpdf2 built-in core fonts (Arial/Helvetica) — no system font path dependencies.
- **ASCII sanitiser `_s()`:** comprehensive Unicode → ASCII mapping before rendering.
- **`_url_to_platform(url)`:** derives readable platform name (e.g. `Github`) from any profile URL for table display.

### 10. Admin User Panel ✅ Phase 5
- Create/update/delete officers, analysts, admins; scrypt-hashed passwords
- **Username-based** — form accepts `username` field (max 20 chars, letters/numbers/underscore/dot)
- Password field is `type="password"` with eye-toggle visibility button
- Source column removed from user table (was always "file" — redundant)
- Helper hint text shown below username and password fields in the form
- Legacy email-keyed accounts auto-migrated to plain username keys on first admin panel load

### 11. Export / Reporting
- **JSON** — Full session payload download
- **CSV** — Flat table of all results
- **PDF** — Professional law-enforcement reports via `pdf_report_service.py`; available on all 4 main modules

### 12. Audit Trail
- Every login, logout, scan, download, admin action written to `audit_logs/police_portal_audit.jsonl`
- Fields: `timestamp_utc`, `action`, `status`, `user_email`, `user_role`, `remote_addr`, `details`

---

## Integrated OSINT Tools

| Tool | Mode | How Integrated | Notes |
|------|------|----------------|-------|
| **Holehe** | Email | Embedded Python library (Sam/Sam/) | async trio, 123 modules |
| **user-scanner** | Email + Username | subprocess + SSE streaming | 195+ platforms, v1.3.6 |
| **Sherlock** | Username | subprocess + SSE streaming | --print-found --no-color |
| **Maigret** | Username | subprocess + SSE streaming | --no-color --no-progressbar |
| **PIL/Pillow** | Image | Direct import | No external binary needed |
| **phonenumbers** | Phone | Direct import | libphonenumber port |
| **OpenAI GPT-4o-mini** | Ask AI | httpx POST to Chat Completions API | Requires OPENAI_API_KEY |
| **fpdf2** | PDF Reports | Direct import in pdf_report_service.py | All 4 modules |
| **nslookup** | Domain | subprocess.run() | System binary |
| **whois** | Domain | subprocess.run() (optional) | Only if whois on PATH |

---

## Frontend / Backend Communication Rules

### Golden Rules (NEVER VIOLATE)
1. **Never show raw CLI output** on frontend — always parse and structure it
2. **Never show raw JSON** on frontend — always render in cards, tables, or structured sections
3. **Never block the UI** — streaming tools (Sherlock, Maigret, user-scanner) must use SSE, not blocking POST
4. **All results must be visually structured** — use cards, badges, progress bars, tables
5. **Maintain professional UX** — navy/khaki color scheme, clean light theme, law-enforcement grade layout

### SSE Pattern (for all subprocess tools)
```
Backend generator → yields: {"type": "result"|"progress"|"complete"|"error", ...}
Frontend EventSource → switches on type:
  "result"   → append table row with fade-in animation + capture to _pdfData
  "progress" → update progress bar width
  "complete" → show summary card, stop animation, close EventSource
  "error"    → show danger alert, close EventSource
```

### Dashboard PDF Pattern (Phase 4)
```
All SSE/AJAX result handlers → push to _pdfData JS object
"Download PDF" button → downloadDashboardPdf() → POST /api/export/dashboard-pdf
Flask → generate_dashboard_pdf(payload) → Response(pdf_bytes, mimetype="application/pdf")
Browser → blob → URL.createObjectURL → synthetic <a> click → revokeObjectURL
```

### Template Inheritance Rules
- All authenticated pages MUST extend `base.html`
- `base.html` handles: navbar, notice bar, Bootstrap CDN, CSS variables
- CSS variables: `--navy: #062952`, `--navy-dark: #041d39`, `--khaki: #cab58a`, `--accent: #f3c14b`
- Login page is standalone (does not extend base.html — correct)
- Child templates use raw CSS in `{% block extra_css %}` — do NOT wrap with `<style>` tags (base.html already renders this block inside a `<style>` tag)

---

## Important Engineering Rules

### Security
- All routes check `_is_authorized()` (session `authorized` key) before serving
- Admin routes additionally check `_is_admin()` (role == "admin")
- Login uses plain username (no email domain) — `_USERNAME_RE = re.compile(r'^[a-zA-Z0-9_.]{1,20}$')`
- Password strength enforced on create/update: 8+ chars, uppercase, digit, special char
- User management uses scrypt password hashing via Werkzeug
- Image uploads validated by MIME magic bytes (not just extension)
- Uploaded images stored with UUID filenames, not original names
- Subprocess calls use `shell=False` and list-format args to prevent injection
- User input sanitized in `UserScannerService._sanitize_input()` before subprocess
- OpenAI API key read exclusively from `OPENAI_API_KEY` env var — never hardcoded
- `session["police_email"]` key retained (now stores username value) to avoid breaking all downstream route references

### File Paths — CRITICAL (Phase 4 fix)
- **All data file paths in `app.py` use absolute paths** anchored to `_APP_DIR = os.path.dirname(os.path.abspath(__file__))`.
- This ensures the app finds its data files regardless of the working directory it is launched from.
- `AUDIT_LOG_PATH`, `POLICE_USERS_FILE`, `OTHER_LINKS_FILE` all use `os.path.join(_APP_DIR, ...)`.
- **Never revert to bare relative paths** like `"data/other_links.json"` — they break when the server is started from any directory other than `Sam/`.

### Subprocess Safety
- Always use `shell=False` for subprocess calls
- Always pass command as a list, never as a string
- **Use `sys.executable`** instead of `"python"` for subprocess calls to Sherlock and Maigret — ensures the correct Python interpreter is always used regardless of PATH
- **Always pass `stdin=subprocess.DEVNULL`** for user-scanner, Sherlock, and Maigret — prevents update-check prompts or other stdin reads from blocking the SSE stream indefinitely
- **Always run Sherlock/Maigret with `cwd=tempfile.mkdtemp()`** and delete the tmpdir in `finally` — prevents output files (`.txt`, reports) from accumulating in the codebase
- **Set `PYTHONUTF8=1` and `FORCE_COLOR=0`** in subprocess env for user-scanner — prevents colorama/cp1252 `UnicodeEncodeError` on Windows when printing checkmark characters
- Timeouts: Holehe=10s, user-scanner=120s/180s, Sherlock=90s, Maigret=120s

### Session Management
- `session["last_infra_scan"]` — stores `{result, query}` after each infra scan; read by `/infra-intel/download/pdf`
- `session["last_ask_ai"]` — stores `{query, result}` after each AI query; read by `/ask-ai/download/pdf`
- `session["last_image_analysis"]` — stores full metadata dict; read by `/image-intel/download/pdf`
- `session["pending_image"]` — stores temp file path for image analysis workflow
- `session["police_email"]`, `session["police_role"]` — user identity

### PDF Generation Rules
- Always import from `services.pdf_report_service` — never duplicate PDF logic per page
- All text must go through `_s()` before passing to fpdf2 (Latin-1 core fonts only)
- Use `_url_to_platform(url)` to extract readable site names from profile URLs
- The `kv()` method uses explicit `set_xy()` + calculated `val_w` — do NOT revert to `multi_cell(0, ...)` after a `cell()` call (fpdf2 2.8.7 bug)
- Row/page limits: cap large result sets at 100 rows per table section; add a "…and N more" note_box

### Audit Logging
- Every significant action must call `_write_audit_log(action, status, details)`
- Include both success and failure events

---

## Known Issues (Priority Ordered)

### ✅ Resolved in Phase 1
1. ~~Flask single-threaded SSE blocking~~ — **FIXED:** `threaded=True` added to `app.run()`.
2. ~~`"python"` in subprocess calls~~ — **FIXED:** All 4 occurrences replaced with `sys.executable` in `app.py`.
3. ~~`BRAND_LOGO_PATH` hardcoded to `rockg` machine~~ — **FIXED:** Now reads `POLICE_BRAND_LOGO_PATH` env var.
4. ~~`start_server.py` contains plaintext secrets~~ — **FIXED:** Secrets removed; script is now portable.
5. ~~No `requirements.txt`~~ — **FIXED:** `requirements.txt` created with all pinned versions.
6. ~~No canonical venv~~ — **FIXED:** `Sam/.venv` created with Python 3.11, all packages installed.

### ✅ Resolved in Phase 2
7. ~~**`username_tools.html` does not extend `base.html`**~~ — **FIXED:** Now extends base.html.
8. ~~**Duplicate `tool-user_scanner` HTML IDs**~~ — **FIXED:** Username group uses `id="tool-user_scanner-u"`.
9. ~~**`userdeep` double-scan issue**~~ — **FIXED:** `startCombinedStreaming` manages both EventSources.
10. ~~**SSE generators leave zombie subprocesses on client disconnect**~~ — **FIXED:** try/finally with `process.kill()` on `GeneratorExit`.
11. ~~**`/ai-investigation-assistant` auth check inconsistency**~~ — **FIXED:** Now uses `_is_authorized()`.

### ✅ Resolved in Phase 3
12. ~~**Fragmented links pages**~~ — **FIXED:** Merged into `other_links.html` + `other_links.json`. Legacy routes redirect.
13. ~~**Static AI assistant**~~ — **FIXED:** Replaced by `ask_ai.html` with live OpenAI GPT-4o-mini backend.
14. ~~**Inconsistent non-professional UI**~~ — **FIXED:** Full frontend overhaul across login, base navbar, main dashboard tool picker, and image intel page.
15. ~~**Bootstrap default badge colors (cyan/yellow) in navbar**~~ — **FIXED:** Glass-chip email badge + khaki gold role badge.
16. ~~**Dark/cyberpunk CSS on image_intel.html**~~ — **FIXED:** Replaced with clean light theme matching rest of app.

### ✅ Resolved in Phase 4
17. ~~**No PDF export on any page**~~ — **FIXED:** `services/pdf_report_service.py` created; PDF buttons added to all 4 modules; download routes added.
18. ~~**Main Dashboard PDF completely non-functional**~~ — **FIXED:** SSE-only architecture meant no server-side results existed. Fixed via `_pdfData` JS accumulator + POST endpoint `/api/export/dashboard-pdf`.
19. ~~**PDF only showed URL lists for Sherlock/Maigret**~~ — **FIXED:** Tables now show Platform, Username, Profile URL, Status columns with `_url_to_platform()` helper.
20. ~~**User-Scanner results missing from PDF**~~ — **FIXED:** Found results captured in `_pdfData.user_scanner_email/username` and included in Dashboard PDF.
21. ~~**Userdeep profiles not captured for PDF**~~ — **FIXED:** `startCombinedStreaming` now pushes to `_pdfData.sherlock_profiles`, `_pdfData.maigret_profiles`, and `_pdfData.userdeep_profiles`.
22. ~~**Navbar branding "SOC/OSINT"**~~ — **FIXED:** Replaced with two-line "Hyderabad City Police / OSINT Portal" in `base.html`.
23. ~~**PDF header showed "HYDERABAD COMMISSIONERATE POLICE"**~~ — **FIXED:** All PDF branding now reads "HYDERABAD CITY POLICE".
24. ~~**`other_links.json` empty / Other Links page shows 0 tools**~~ — **FIXED:** File populated with 21 tools across 8 categories.
25. ~~**Relative data file paths break when server started outside `Sam/`**~~ — **FIXED:** `_APP_DIR` constant added; `AUDIT_LOG_PATH`, `POLICE_USERS_FILE`, `OTHER_LINKS_FILE` all use `os.path.join(_APP_DIR, ...)`.
26. ~~**No Master Prompt page**~~ — **FIXED:** `/master-prompt` route + `master_prompt.html` template added; navbar tab added to `base.html`.

### ✅ Resolved in Phase 5
27. ~~**Email domain-locked login**~~ — **FIXED:** `ALLOWED_EMAIL_DOMAINS` removed; login now accepts plain `username` field with no domain restriction.
28. ~~**Admin panel used email input with domain hint text**~~ — **FIXED:** Form switched to `type="text" name="username"`; domain text removed; username/password rules shown as helper hints; Source column removed from user table.
29. ~~**Password field visible in admin panel**~~ — **FIXED:** `type="password"` with eye-toggle visibility button (admin panel + login page).
30. ~~**`police_users.json` stored email-keyed accounts**~~ — **FIXED:** File migrated to plain username keys (`officer1@tspolice.gov.in` → `officer1`); `_migrate_email_keys()` handles any remaining legacy entries automatically.
31. ~~**Disposable Email Risk, Phone Intelligence, Email Breach & Intel Pivots outputs were plain text**~~ — **FIXED:** All three `render*` JS functions rewritten with color-coded pill badges, structured key/value grids, and styled pivot link cards.
32. ~~**Three fast-result cards used inconsistent layout and plain intel-box style**~~ — **FIXED:** All three cards now use navy gradient card headers matching Holehe/Sherlock/Maigret sections; laid out side-by-side in equal `col-md-4` columns.

### ✅ Resolved in Phase 6
33. ~~**Sherlock and Maigret write `<username>.txt` / report files into the codebase**~~ — **FIXED:** Both SSE generators now run the subprocess with `cwd=tempfile.mkdtemp()`; the temp dir is deleted in the `finally` block via `shutil.rmtree(tmpdir, ignore_errors=True)`. No output files ever land in `Sam/`.
34. ~~**User-Scanner username SSE showed "Connection Error" immediately**~~ — **FIXED:** Root cause was `user-scanner`'s update-check prompt blocking on stdin (inherited from Flask's process). Fixed by adding `stdin=subprocess.DEVNULL` to the Popen call. Also added `PYTHONUTF8=1` and `FORCE_COLOR=0` to prevent the colorama/cp1252 `UnicodeEncodeError` crash on Windows when user-scanner tries to print checkmark characters.
35. ~~**Unhandled exception in `stream_scan` generate() crashed SSE connection**~~ — **FIXED:** `generate()` body now wrapped in `try/except`; any unhandled exception yields `{"type": "error", "message": "..."}` instead of dropping the HTTP connection. Also switched to `json.dumps(..., ensure_ascii=False)` to safely pass Unicode platform names/URLs.

### ✅ Resolved in Phase 7
36. ~~**Dashboard tool picker defaulted to only Holehe selected on page load**~~ — **FIXED:** Two-part fix: (1) Flask GET route changed from `selected_tools=["holehe"]` to `selected_tools=[]`; (2) Jinja conditions in `index.html` changed from `{% if selected_tools and tool.id in selected_tools %}` to `{% if not selected_tools or tool.id in selected_tools %}` — so an empty list means "select everything". Server now renders all cards pre-selected, all checkboxes pre-checked, all buttons showing "✓ Selected" with zero JS dependency for initial state.
37. ~~**No global "Select All Tools" control**~~ — **FIXED:** New pill-shaped global bar added above all sections with `id="select-all-global"`. Wired to `toggleAllTools()` which syncs every section checkbox and card simultaneously.
38. ~~**Section "Select All" labels were ambiguous**~~ — **FIXED:** Renamed to "Select All Email Tools", "Select All Username Tools", "Select All Phone Tools".
39. ~~**Deselecting one card did not update parent section or global checkboxes**~~ — **FIXED:** Added `syncSectionCheckbox()` and `syncGlobalCheckbox()` helpers. `toggleTile()` now calls the appropriate section sync + global sync after every card click. All section `toggle*Tools()` functions call `syncGlobalCheckbox()` after toggling.

### Medium (Remaining)
40. **Tools hidden from UI but still coded:** `gravatar`, `domain`, `mxsec`, `whois`, and `username` tools have full backend implementations but are absent from `AVAILABLE_TOOLS` — unreachable from UI.

### Low (Remaining)
41. **Audit log no rotation:** Single append-only JSONL file with no size limit.
42. **Holehe `run_holehe()` is synchronous-blocking:** Can take 10–30s. Future: stream via SSE.
43. **Production deployment needs gunicorn**, not the Flask dev server.

---

## ✅ Phase 1 Cleanup

```
DELETED: osint_final_project/__MACOSX/
DELETED: osint_final_project/.venv/                     ← Broken venv (rockg/Python 3.14)
DELETED: osint_final_project/venv/                      ← macOS Homebrew Python 3.12 venv
DELETED: osint_final_project/Sam/holehe.egg-info/ + Sam egg/ + build/
DELETED: templates/phone_tools.html.bak + alizayed.txt files
CREATED: Sam/.venv/, Sam/requirements.txt, Sam/.env.example
UPDATED: Sam/start_server.py (portable, no hardcoded secrets)
```

## ✅ Phase 3 Changes

```
REPLACED: templates/osint_links.html + templates/commercial_links.html
       → templates/other_links.html  (unified admin-managed links directory)

REPLACED: templates/ai_assistant.html (static guide)
       → templates/ask_ai.html       (live OpenAI GPT-4o-mini copilot)

REPLACED: data/osint_links.json + data/commercial_links.json
       → data/other_links.json       (merged links store)

UPDATED: templates/base.html         (nav-pill classes, glass email badge, khaki role badge, footer)
UPDATED: templates/login.html        (professional navy theme, btn-login, login-input classes)
UPDATED: templates/index.html        (tc-tool-card picker, unified streaming card headers)
UPDATED: templates/image_intel.html  (light theme, upload-card, intel-card, intel-card-header classes)
UPDATED: app.py                      (/other-links, /ask-ai, /api/ask-ai routes; legacy redirects;
                                      OPENAI_API_KEY env var; _AI_SYSTEM_PROMPT constant)
```

## ✅ Phase 4 Changes

```
CREATED: services/pdf_report_service.py
           — _IntelReport base FPDF class (shared header/footer/helpers)
           — generate_dashboard_pdf()  → Main Dashboard PDF
           — generate_infra_pdf()      → Infrastructure Intel PDF
           — generate_image_pdf()      → Image Intel PDF
           — generate_ask_ai_pdf()     → Ask AI PDF
           — _s() ASCII sanitiser, _url_to_platform() URL→name helper
           — Branding: "HYDERABAD CITY POLICE" on all pages

CREATED: templates/master_prompt.html
           — Static reference page, extends base.html
           — Verbatim master investigation prompt in dark monospace box
           — Copy Prompt button with clipboard API + execCommand fallback
           — 6-step instruction cards

UPDATED: templates/base.html
           — Navbar branding: "SOC/OSINT" → "Hyderabad City Police / OSINT Portal" (two lines)
           — Added "🧠 Master Prompt" nav-pill tab

UPDATED: templates/index.html
           — Added _pdfData JS accumulator with all result keys
           — User-Scanner found results captured in user_scanner_email/username arrays
           — Sherlock/Maigret/userdeep profiles captured in startCombinedStreaming handlers
           — Download condition fixed: {% if email or username or phone %}
           — PDF button changed from broken <a href> to <button onclick="downloadDashboardPdf()">

UPDATED: templates/ask_ai.html
           — Added PDF download button (links to /ask-ai/download/pdf)

UPDATED: templates/image_intel.html
           — Added PDF download button alongside JSON button

UPDATED: templates/infrastructure_intel.html (assumed name — verify actual filename)
           — Added PDF download button inside {% if result %} block

UPDATED: routes/image_routes.py
           — Added GET /image-intel/download/pdf route
           — Reads session['last_image_analysis'] → generate_image_pdf()

UPDATED: app.py
           — Added _APP_DIR = os.path.dirname(os.path.abspath(__file__))
           — AUDIT_LOG_PATH, POLICE_USERS_FILE, OTHER_LINKS_FILE now use os.path.join(_APP_DIR, ...)
           — session['last_infra_scan'] stored after each infra scan
           — session['last_ask_ai'] stored after each /api/ask-ai call
           — Added GET /infra-intel/download/pdf route
           — Added GET /ask-ai/download/pdf route
           — Added GET /master-prompt route
           — Added POST /api/export/dashboard-pdf route
             (accepts JSON _pdfData, maps to generate_dashboard_pdf payload)
           — Added user_scanner_email + user_scanner_username to dashboard PDF payload

UPDATED: data/other_links.json
           — Pre-populated with 21 tools across 8 categories:
             Username Intelligence: WhatsMyName, OSINT.ROCKS
             Email Intelligence: BehindTheEmail
             Infrastructure Intelligence: DNSDumpster, DNSlytics, Shodan, who.is,
                                          Censys, IPInfo, WHOIS DomainTools
             Threat Intelligence: AbuseIPDB
             Metadata Analysis: FotoForensics, Pic2Map, TinEye, AI or Not
             Malware Analysis: any.run, VirusTotal
             DFIR: SpiderFoot
             Reconnaissance: MarineTraffic, FaceCheck.ID, GSTIN & Business Finder
```

---

## Deployment Considerations

### Current (Dev) Launch
```powershell
# Option A: from within Sam/
cd osint_final_project\Sam
.\.venv\Scripts\Activate.ps1
$env:APP_SECRET_KEY = "your-strong-random-32-char-secret"
$env:POLICE_PORTAL_PASSWORD = "YourSecurePassword@123"   # default admin password
$env:POLICE_BRAND_LOGO_PATH = "C:\path\to\police_emblem.png"   # optional
$env:OPENAI_API_KEY = "sk-..."                                  # required for Ask AI
python start_server.py

# Option B: from repo root (start_server.py auto-chdirs to Sam/)
python osint_final_project\Sam\start_server.py
```

### Minimum Required Environment Variables
```
APP_SECRET_KEY              Strong random secret (32+ chars)
POLICE_PORTAL_PASSWORD      Default admin password (default: ChangeMe@123) — change before deployment
POLICE_BRAND_LOGO_PATH      Absolute path to the police emblem PNG (optional)
POLICE_AUDIT_LOG_PATH       Absolute path to audit JSONL file (default: <Sam dir>/audit_logs/...)
POLICE_USERS_FILE           Absolute path to user accounts JSON (default: <Sam dir>/data/police_users.json)
OTHER_LINKS_FILE            Absolute path to other_links JSON (default: <Sam dir>/data/other_links.json)
OPENAI_API_KEY              OpenAI API key — required for /ask-ai feature

REMOVED (Phase 5): POLICE_ALLOWED_DOMAINS — email domain restriction eliminated; login is now username-based
```

### Production Deployment Requirements
1. **Use gunicorn with threading** — `gunicorn -w 4 --threads 4 -b 0.0.0.0:8000 app:app`
2. **Reverse proxy** (nginx/caddy) for TLS and `X-Accel-Buffering: no` header for SSE
3. **Never run `debug=True`** in production

---

## App Configuration Reference

```python
# app.py top-level constants
_APP_DIR = os.path.dirname(os.path.abspath(__file__))   # always Sam/ regardless of launch CWD

AVAILABLE_TOOLS = [
    {"id": "holehe",       "label": "Holehe Email Footprint"},
    {"id": "user_scanner", "label": "User-Scanner OSINT Engine (195+ Platforms)"},
    {"id": "disposable",   "label": "Disposable Email Risk Check"},
    {"id": "emailpivots",  "label": "Email Breach & Intel Pivots"},
    {"id": "phone",        "label": "Phone Intelligence"},
    {"id": "sherlock",     "label": "Sherlock Username Deep Scan"},
    {"id": "maigret",      "label": "Maigret Username Deep Scan"},
    {"id": "userdeep",     "label": "Username Deep Scan (Sherlock + Maigret)"},
]

LINK_CATEGORIES = [
    "Username Intelligence", "Email Intelligence", "Infrastructure Intelligence",
    "Threat Intelligence", "Metadata Analysis", "DFIR", "Malware Analysis", "Reconnaissance",
]

EMAIL_BASED_TOOLS    = {"holehe", "user_scanner", "disposable", "emailpivots"}
USERNAME_BASED_TOOLS = {"username", "sherlock", "maigret", "userdeep"}
PHONE_BASED_TOOLS    = {"phone"}
```

---

## CSS Design System

```css
/* base.html CSS variables — use everywhere, never hardcode colors */
--navy:       #062952   /* Primary dark blue — headers, buttons */
--navy-dark:  #041d39   /* Darker navy — header background */
--khaki:      #cab58a   /* Gold accent — header border, service tiles */
--khaki-soft: #e2d3b2   /* Soft khaki — notice bar */
--accent:     #f3c14b   /* Bright gold — CTA buttons, highlights */
--surface:    #f4f7fb   /* Page background */

/* Base component classes */
.portal-card    /* Main content cards */
.section-head   /* Navy gradient card headers */
.intel-box      /* Inner result boxes */
.btn-intel      /* Primary action button (navy) */
.service-tile   /* Left-bordered info tiles */
.tag-hit        /* Green "found" pill badge */

/* Phase 3 additions — base.html */
.nav-pill           /* Navbar link: ghost pill, rgba white border */
.nav-pill-active    /* Active navbar link: white bg, navy text */

/* Phase 3 additions — index.html tool picker */
.tool-section-label /* Section header above tool card groups */
.tc-tool-card       /* Tool picker card */
.tc-title           /* Tool card title */
.tc-desc            /* Tool card description */
.tc-footer          /* Tool card bottom row with Select button */
.tc-select-btn      /* "Select Tool" / "✓ Selected" toggle button */
.badge-integrated   /* Green badge: direct library integration */
.badge-streaming    /* Blue badge: SSE streaming tool */
.badge-pivot        /* Amber badge: pivot/link generator */

/* Phase 3 additions — image_intel.html */
.upload-card        /* White wrapper card for upload UI */
.upload-zone        /* Dashed-border drag-drop area */
.intel-card         /* White result card */
.intel-card-header  /* Navy gradient header on intel cards */
.status-badge.*     /* Pastel semantic status colors */
.scanning-overlay   /* Semi-transparent navy overlay during scan */

/* Phase 4 additions — master_prompt.html */
.mp-hero            /* Dark navy gradient hero header */
.mp-step-card       /* Instruction step card with numbered circle */
.mp-prompt-box      /* Dark monospace prompt display box (#0d1117 bg) */
.btn-copy           /* Copy Prompt button */
```

---

## SSE Event Schema

```json
{"type": "result",   "data": {platform, found, url, category, status}, "found_count": N, "checked_count": N}
{"type": "progress", "message": "...", "found_count": N, "checked_count": N}
{"type": "complete", "found_count": N, "checked_count": N, "duration": N}
{"type": "error",    "message": "..."}
```

## Dashboard PDF Data Schema (`_pdfData` JS object → POST body)

```json
{
  "email":                  "target@example.com",
  "username":               "targetuser",
  "phone":                  "+911234567890",
  "selected_tools":         ["holehe", "sherlock", "user_scanner", ...],
  "holehe":                 [{domain, exists, emailrecovery, phoneNumber}, ...],
  "sherlock_profiles":      ["https://github.com/user", ...],
  "maigret_profiles":       ["https://medium.com/@user", ...],
  "userdeep_profiles":      ["https://github.com/user", ...],
  "user_scanner_email":     [{platform, url, category, status}, ...],
  "user_scanner_username":  [{platform, url, category, status}, ...],
  "disposable_result":      {domain, is_disposable, risk_level},
  "email_pivots_result":    {email, pivots: [{name, url}, ...]},
  "phone_result":           {valid, e164, international, national, carrier, region, ...},
  "username_footprint_result": {username, platforms: [{name, url}, ...]}
}
```

---

## Future Roadmap Ideas

### High Priority
- [ ] **Holehe SSE streaming** — Currently blocks for 10–30s. Stream results live like Sherlock/Maigret
- [ ] **Restore hidden tools to UI** — `gravatar`, `domain`, `mxsec`, `whois` are coded and functional
- [ ] **Audit log rotation** — weekly or by size; or in-app log viewer for admins

### Medium Priority
- [ ] **Split app.py into Blueprints** — email_bp, phone_bp, username_bp, auth_bp, admin_bp
- [ ] **Case/Investigation tracking** — Link scans to a named case, persist results to file/DB
- [ ] **Network graph visualization** — Show relationships between found profiles (D3.js or vis.js)
- [ ] **Audit log viewer** — In-app table view of audit log with filtering (admin only)
- [ ] **Bulk input mode** — Run same tool against a list of emails/usernames

### Future / Advanced
- [ ] **IP Intelligence module** — Geolocation, ASN lookup, threat reputation (AbuseIPDB, Shodan)
- [ ] **Report templates** — Structured PDF with cover page, case number, officer name
- [ ] **Docker containerization** — Package entire platform with all tools pre-installed
- [ ] **WebSocket upgrade** — Replace SSE with WebSocket for bidirectional progress control

---

## ✅ Phase 5 Changes

```
UPDATED: app.py
           — Removed ALLOWED_EMAIL_DOMAINS constant entirely
           — Added _USERNAME_RE = re.compile(r'^[a-zA-Z0-9_.]{1,20}$')
           — Added _validate_username(username) → error string or None
           — Added _validate_password_strength(password) → error string or None
           — Added _migrate_email_keys(accounts) → strips @domain from legacy JSON keys
           — Updated _load_police_accounts(): default admin key is "admin" (not email), migrates on load
           — Replaced login() route: accepts name="username", no domain check
           — Replaced admin_users() route: uses name="username", validates with new functions,
             calls _migrate_email_keys() and saves permanently on first access

UPDATED: templates/login.html
           — Field changed: type="email" name="police_email" → type="text" name="username"
           — Placeholder: "e.g. officer_01"
           — Removed allowed-domains Jinja loop and domain footer text
           — Added password visibility eye-toggle button (inline SVG, toggleLoginPw() JS)
           — Title/heading updated; same visual design preserved

UPDATED: templates/admin_users.html
           — Form: type="email" name="email" → type="text" name="username" with maxlength="20" pattern
           — Password field: type="text" → type="password" with eye-toggle button (toggleAdminPw() JS)
           — Removed "Allowed domains: tspolice.gov.in, hydtspolice.gov.in" paragraph
           — Added username helper text: max 20 chars, letters/numbers/underscore/dot
           — Added password helper text: 8+ chars, uppercase, number, special char required
           — Table header "Email" → "Username"; row {{ user.email }} → {{ user.username }}
           — Delete form: name="email" → name="username"; hidden value uses {{ user.username }}
           — Source column removed from user table entirely

UPDATED: data/police_users.json
           — Keys migrated: "officer1@tspolice.gov.in" → "officer1" (all 3 existing accounts)
           — Passwords and roles preserved unchanged

UPDATED: templates/index.html
           — renderDisposable(): rewritten with color-coded pill badge, 2-col info grid (Domain / Risk Level)
           — renderPhone(): rewritten with valid/invalid badge, key-value table, pivot links as pill buttons
           — renderEmailPivots(): rewritten with colored card buttons per pivot (amber/blue/purple/green/pink)
           — Three fast-result cards (Disposable, Phone, Pivots) restyled to match Holehe card design:
             navy gradient header (linear-gradient 135deg #062952→#0c3f7b), white card body
           — Layout changed from col-md-3 / col-md-6 / col-md-6 → equal col-md-4 / col-md-4 / col-md-4
             so all three sit side-by-side in one row
```

---

## ✅ Phase 6 Changes

```
UPDATED: app.py
           — Added import tempfile (top-level)
           — stream_sherlock(): subprocess now runs with cwd=tempfile.mkdtemp();
             tmpdir deleted via shutil.rmtree(tmpdir, ignore_errors=True) in finally block;
             removed local `import shutil` (already imported at top level)
           — stream_maigret(): same tmpdir pattern applied
           — stream_scan() generate(): wrapped body in try/except to yield error SSE event
             instead of crashing the HTTP connection on unhandled exceptions;
             switched to json.dumps(..., ensure_ascii=False) for Unicode safety

UPDATED: services/user_scanner_service.py
           — scan_streaming() Popen call: added stdin=subprocess.DEVNULL (fixes update-check
             prompt blocking on stdin when running under Flask)
           — Added PYTHONUTF8=1 and FORCE_COLOR=0 to subprocess env (prevents colorama
             UnicodeEncodeError on Windows with cp1252 when printing checkmark characters)
           — Removed COLORAMA_INIT=False (not a real colorama env var; replaced by FORCE_COLOR=0)
```

---

## ✅ Phase 7 Changes

```
UPDATED: app.py
           — GET / route: changed selected_tools=["holehe"] → selected_tools=[]
             so the dashboard renders with all tools pre-selected on every fresh page load

UPDATED: templates/index.html
           — Global "Select All Tools" bar: new pill-shaped control inserted above GROUP 1
             (id="select-all-global", onchange="toggleAllTools(this)")
             Styled with #edf3fd background + 1.5px #c0d4ef border; 0.86rem bold navy label
           — Section "Select All" labels renamed:
               "Select All" → "Select All Email Tools"    (id="select-all-email")
               "Select All" → "Select All Username Tools" (id="select-all-username")
               "Select All" → "Select All Phone Tools"    (id="select-all-phone")
           — Jinja tool-card conditions changed (all 9 occurrences across 3 groups):
               {% if selected_tools and tool.id in selected_tools %}
             → {% if not selected_tools or tool.id in selected_tools %}
             Applied to: card `selected` CSS class, button text "✓ Selected", checkbox `checked` attr
             Effect: empty selected_tools → all tools rendered pre-selected server-side; no JS flash
           — JS additions and changes:
               NEW syncSectionCheckbox(sectionId, toolClass): sets section checkbox to
                 checked / unchecked / indeterminate based on its tool checkboxes
               NEW syncGlobalCheckbox(): sets global checkbox to
                 checked / indeterminate / unchecked based on ALL tool checkboxes
               NEW toggleAllTools(source): checks/unchecks all tool checkboxes + cards +
                 resets all 3 section checkboxes (no indeterminate)
               UPDATED toggleTile(): after toggling, calls syncSectionCheckbox for the
                 correct section class + syncGlobalCheckbox
               UPDATED toggleEmailTools(): calls syncGlobalCheckbox after toggling
               UPDATED toggleUsernameTools(): calls syncGlobalCheckbox after toggling
               UPDATED togglePhoneTools(): calls syncGlobalCheckbox after toggling
               UPDATED DOMContentLoaded init: detects if any checkbox is pre-checked (POST
                 scan); if none are, selects all; always syncs section + global checkboxes
```

---

*Last updated: 2026-05-12 — Phase 7: dashboard tool picker defaults to all-selected on page load; global Select All Tools control; section label clarifications; full selection synchronization.*
