from flask import Flask, render_template, request, session, redirect, url_for, Response, send_file, jsonify
import trio
import httpx
import Sam.core as hc
import hashlib
import socket
import subprocess
from urllib.parse import quote, urlparse
import phonenumbers
from phonenumbers import carrier, geocoder, number_type, timezone as pn_timezone, PhoneNumberType
import os
import io
import csv
import json
from datetime import datetime, timezone as dt_timezone
import shutil
import re
import sys
import uuid
import tempfile
from concurrent.futures import ThreadPoolExecutor

try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env'))
except ImportError:
    pass

# Add project root to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from services.user_scanner_service import get_scanner_service, UserScannerService
from services.urlscan_service import query_urlscan
from services.instagram_service import run_instagram_sniffer

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", os.getenv("APP_SECRET_KEY", "change-this-in-production"))

# Database
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', f'sqlite:///{os.path.join(os.path.dirname(os.path.abspath(__file__)), "police_portal.db")}')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['TEMPLATES_AUTO_RELOAD'] = True

# Session
from datetime import timedelta as _td
app.config['PERMANENT_SESSION_LIFETIME'] = _td(days=30)
app.config['SESSION_COOKIE_HTTPONLY']    = True
app.config['SESSION_COOKIE_SAMESITE']   = 'Lax'

# Initialize extensions
from extensions import db as _db, limiter as _limiter
_db.init_app(app)
_limiter.init_app(app)

# Register blueprints
from routes.image_routes import image_bp
app.register_blueprint(image_bp)
from routes.auth import auth_bp
app.register_blueprint(auth_bp)
from routes.admin import admin_bp
app.register_blueprint(admin_bp)

# ── Return JSON (not HTML) for errors on /api/* and blueprint API routes ──────
from flask import jsonify as _jsonify

@app.errorhandler(404)
def _err_404(e):
    from flask import request as _req
    if _req.path.startswith('/api/') or _req.path.startswith('/image-intel/') \
            or _req.is_json or _req.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return _jsonify({"error": f"Route not found: {_req.path}"}), 404
    return e

@app.errorhandler(500)
def _err_500(e):
    from flask import request as _req
    import traceback, logging as _logging
    _logging.getLogger(__name__).error("Unhandled 500: %s\n%s", e, traceback.format_exc())
    if _req.path.startswith('/api/') or _req.path.startswith('/image-intel/') \
            or _req.is_json or _req.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return _jsonify({"error": f"Internal server error: {str(e)[:200]}"}), 500
    return e

# Create tables and seed default admin
def _create_initial_admin():
    from models import User as _User
    from routes.auth import hash_password as _hp
    if _User.query.count() > 0:
        return
    username = os.getenv('ADMIN_DEFAULT_USERNAME', os.getenv('INITIAL_ADMIN_USERNAME', 'admin'))
    password = os.getenv('ADMIN_DEFAULT_PASSWORD', os.getenv('INITIAL_ADMIN_PASSWORD', 'ChangeMe@123'))
    admin = _User(
        full_name     = 'Administrator',
        username      = username,
        password_hash = _hp(password),
        role          = 'admin',
        is_active     = True,
    )
    _db.session.add(admin)
    _db.session.commit()
    print(f"[OSINT Portal] Default admin created: username={username}")

with app.app_context():
    _db.create_all()
    _create_initial_admin()

class Args:
    onlyused = False
    nocolor = True
    noclear = True
    nopasswordrecovery = False
    csvoutput = False
    timeout = 10

AVAILABLE_TOOLS = [
    {"id": "holehe",           "label": "Holehe Email Footprint"},
    {"id": "user_scanner",     "label": "User-Scanner OSINT Engine (195+ Platforms)"},
    {"id": "disposable",       "label": "Disposable Email Risk Check"},
    {"id": "emailpivots",      "label": "Email Breach & Intel Pivots"},
    {"id": "behindtheemail",   "label": "BehindTheEmail Intelligence"},
    {"id": "phone",            "label": "Phone Intelligence (Metadata/Search)"},
    {"id": "sherlock",         "label": "Sherlock Username Deep Scan"},
    {"id": "maigret",          "label": "Maigret Username Deep Scan"},
    {"id": "userdeep",         "label": "Username Deep Scan (Sherlock + Maigret)"},
]

EMAIL_BASED_TOOLS = {"holehe", "user_scanner", "disposable", "emailpivots", "behindtheemail"}
BEHINDTHEEMAIL_API_KEY = os.getenv("BEHINDTHEEMAIL_API_KEY", "")
USER_SCANNER_TOOLS = {"user_scanner"}
USERNAME_BASED_TOOLS = {"username", "sherlock", "maigret", "userdeep"}
PHONE_BASED_TOOLS = {"phone"}
_APP_DIR = os.path.dirname(os.path.abspath(__file__))
AUDIT_LOG_PATH = os.getenv("POLICE_AUDIT_LOG_PATH", os.path.join(_APP_DIR, "audit_logs", "police_portal_audit.jsonl"))
BRAND_LOGO_PATH = os.getenv("POLICE_BRAND_LOGO_PATH", "")

USERNAME_PLATFORMS = [
    {"name": "GitHub", "url": "https://github.com/{username}"},
    {"name": "GitLab", "url": "https://gitlab.com/{username}"},
    {"name": "Instagram", "url": "https://www.instagram.com/{username}/"},
    {"name": "Pinterest", "url": "https://www.pinterest.com/{username}/"},
    {"name": "TikTok", "url": "https://www.tiktok.com/@{username}"},
    {"name": "Medium", "url": "https://medium.com/@{username}"},
    {"name": "Tumblr", "url": "https://{username}.tumblr.com"},
    {"name": "Vimeo", "url": "https://vimeo.com/{username}"},
    {"name": "Keybase", "url": "https://keybase.io/{username}"},
    {"name": "Behance", "url": "https://www.behance.net/{username}"},
    {"name": "Docker Hub", "url": "https://hub.docker.com/u/{username}"},
]



LINK_CATEGORIES = [
    "Username Intelligence",
    "Email Intelligence",
    "Infrastructure Intelligence",
    "Threat Intelligence",
    "Metadata Analysis",
    "DFIR",
    "Malware Analysis",
    "Reconnaissance",
]

OTHER_LINKS_FILE = os.getenv("OTHER_LINKS_FILE", os.path.join(_APP_DIR, "data", "other_links.json"))


def _load_other_links():
    if not os.path.exists(OTHER_LINKS_FILE):
        return []
    try:
        with open(OTHER_LINKS_FILE, "r", encoding="utf-8") as f:
            raw = json.load(f)
        if isinstance(raw, list):
            return raw
    except Exception:
        pass
    return []


def _save_other_links(links):
    os.makedirs(os.path.dirname(OTHER_LINKS_FILE), exist_ok=True)
    with open(OTHER_LINKS_FILE, "w", encoding="utf-8") as f:
        json.dump(links, f, indent=2, ensure_ascii=False)


def _is_admin():
    return session.get('police_role') == 'admin'


def _write_audit_log(action, status="success", details=None):
    details = details or {}
    os.makedirs(os.path.dirname(AUDIT_LOG_PATH), exist_ok=True)
    entry = {
        "timestamp_utc": datetime.now(dt_timezone.utc).isoformat(),
        "action": action,
        "status": status,
        "user_email": session.get("police_email"),
        "user_role": session.get("police_role"),
        "remote_addr": request.headers.get("X-Forwarded-For", request.remote_addr),
        "details": details,
    }
    with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def _log_activity(tool_name, action_type, target_input=None, metadata=None, status='success'):
    """Log officer investigation activity to the DB. Never raises."""
    try:
        from services.activity_logger_service import log_activity
        log_activity(
            user_id      = session.get('user_id'),
            username     = session.get('police_email', ''),
            full_name    = session.get('full_name', ''),
            tool_name    = tool_name,
            action_type  = action_type,
            target_input = target_input,
            metadata     = metadata,
            status       = status,
        )
    except Exception:
        pass


@app.route('/web-links')
def web_links():
    return redirect(url_for('other_links'))


@app.route('/commercial-links')
def commercial_links():
    return redirect(url_for('other_links'))


@app.route('/other-links', methods=['GET', 'POST'])
def other_links():
    if not _is_authorized():
        return redirect(url_for('login'))

    error = None
    success = None
    links = _load_other_links()

    if request.method == 'POST':
        if request.form.get('action') == 'delete':
            if not _is_admin():
                _write_audit_log("other_links_delete_attempt", "failed", {"reason": "not_admin"})
                return redirect(url_for("other_links"))
            try:
                index = int(request.form.get('link_index', -1))
                if 0 <= index < len(links):
                    deleted = links.pop(index)
                    _save_other_links(links)
                    success = "Link deleted successfully."
                    _write_audit_log("other_links_delete", "success", {
                        "title": deleted.get("title", ""), "url": deleted.get("url", "")
                    })
                else:
                    error = "Invalid link index."
            except (ValueError, TypeError):
                error = "Invalid request."
        else:
            if not _is_admin():
                _write_audit_log("other_links_add_attempt", "failed", {"reason": "not_admin"})
                return redirect(url_for("other_links"))
            title       = request.form.get('title', '').strip()
            url         = request.form.get('url', '').strip()
            category    = request.form.get('category', '').strip()
            free_paid   = request.form.get('free_paid', 'Free').strip()
            description = request.form.get('description', '').strip()
            if not title or not url or not category:
                error = "Title, URL, and Category are required."
            else:
                if not re.match(r'https?://', url):
                    url = 'https://' + url
                links.append({
                    "title":       title,
                    "url":         url,
                    "category":    category,
                    "free_paid":   free_paid,
                    "description": description,
                    "added_by":    session.get("police_email", "unknown"),
                    "added_at":    datetime.now(dt_timezone.utc).isoformat()
                })
                _save_other_links(links)
                success = f"Link '{title}' added successfully."
                _write_audit_log("other_links_add", "success", {
                    "title": title, "url": url, "category": category
                })

    # Stamp each link with its flat-list index so the template can build delete forms correctly.
    for i, link in enumerate(links):
        link['_idx'] = i

    grouped = {cat: [] for cat in LINK_CATEGORIES}
    for link in links:
        cat = link.get("category", "")
        if cat in grouped:
            grouped[cat].append(link)
        else:
            grouped.setdefault("Other", []).append(link)

    return render_template(
        'other_links.html',
        grouped=grouped,
        categories=LINK_CATEGORIES,
        links=links,
        error=error,
        success=success,
        police_email=session.get("police_email", ""),
        police_role=session.get("police_role", "")
    )


def _is_authorized():
    return bool(session.get('authorized'))


@app.route('/login')
def login():
    return redirect(url_for('auth.login'))


@app.route('/logout')
def logout():
    return redirect(url_for('auth.logout'))


@app.route('/profile', methods=['GET'])
def profile():
    if not _is_authorized():
        return redirect(url_for('auth.login'))
    from models import User as _User
    user = _User.query.get(session.get('user_id'))
    if not user:
        return redirect(url_for('auth.logout'))
    return render_template('profile.html', user=user,
                           error=request.args.get('error'),
                           success=request.args.get('success'))


@app.route('/profile/update', methods=['POST'])
def profile_update():
    if not _is_authorized():
        return redirect(url_for('auth.login'))
    from models import User as _User
    user = _User.query.get(session.get('user_id'))
    if not user:
        return redirect(url_for('auth.logout'))

    full_name = request.form.get('full_name', '').strip()
    if not full_name:
        return redirect(url_for('profile', error="Full name is required."))

    user.full_name = full_name
    _db.session.commit()
    session['full_name'] = full_name
    return redirect(url_for('profile', success="Profile updated successfully."))


@app.route('/profile/change-password', methods=['POST'])
def profile_change_password():
    if not _is_authorized():
        return redirect(url_for('auth.login'))
    from models import User as _User
    from routes.auth import validate_password as _vp, check_password as _cp, hash_password as _hp
    user = _User.query.get(session.get('user_id'))
    if not user:
        return redirect(url_for('auth.logout'))

    current_pw = request.form.get('current_password', '')
    new_pw     = request.form.get('new_password', '')
    confirm_pw = request.form.get('confirm_password', '')

    if not _cp(current_pw, user.password_hash):
        return redirect(url_for('profile', error="Current password is incorrect."))
    if new_pw != confirm_pw:
        return redirect(url_for('profile', error="New passwords do not match."))
    if (pw_err := _vp(new_pw)):
        return redirect(url_for('profile', error=pw_err))

    user.password_hash = _hp(new_pw)
    _db.session.commit()
    return redirect(url_for('profile', success="Password changed successfully."))


@app.route('/brand-logo')
def brand_logo():
    if BRAND_LOGO_PATH and os.path.exists(BRAND_LOGO_PATH):
        return send_file(BRAND_LOGO_PATH)
    # Fallback: serve from static/police_logo.png if dropped there
    static_logo = os.path.join(_APP_DIR, 'static', 'police_logo.png')
    if os.path.exists(static_logo):
        return send_file(static_logo)
    return "", 404




@app.route('/', methods=['GET', 'POST'])
def index():
    if not _is_authorized():
        return redirect(url_for("login"))

    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        username = request.form.get('username', '').strip()
        phone = request.form.get('phone', '').strip()
        selected_tools = request.form.getlist('tools')
        # Strip tools whose required input field was not provided
        if not email:
            selected_tools = [t for t in selected_tools if t not in EMAIL_BASED_TOOLS]
        if not username:
            selected_tools = [t for t in selected_tools if t not in USERNAME_BASED_TOOLS]
        if not phone:
            selected_tools = [t for t in selected_tools if t not in PHONE_BASED_TOOLS]
        # If nothing survived (e.g. form submitted before JS auto-selected), derive from filled fields
        if not selected_tools:
            if email:    selected_tools += [t["id"] for t in AVAILABLE_TOOLS if t["id"] in EMAIL_BASED_TOOLS]
            if username: selected_tools += [t["id"] for t in AVAILABLE_TOOLS if t["id"] in USERNAME_BASED_TOOLS]
            if phone:    selected_tools += [t["id"] for t in AVAILABLE_TOOLS if t["id"] in PHONE_BASED_TOOLS]

        needs_email = any(tool in EMAIL_BASED_TOOLS for tool in selected_tools)
        needs_username = any(tool in USERNAME_BASED_TOOLS for tool in selected_tools)
        needs_phone = any(tool in PHONE_BASED_TOOLS for tool in selected_tools)

        if needs_email and not hc.is_email(email):
            return render_template(
                'index.html',
                error="Please enter a valid email address.",
                available_tools=AVAILABLE_TOOLS,
                selected_tools=selected_tools,
                email=email,
                username=username,
                phone=phone
            )

        if needs_username and not username:
            username = email.split("@")[0].strip().lower() if hc.is_email(email) else ""

        if needs_username and not username:
            return render_template(
                'index.html',
                error="Please enter a username for username footprint checks.",
                available_tools=AVAILABLE_TOOLS,
                selected_tools=selected_tools,
                email=email,
                username=username,
                phone=phone
            )

        if needs_phone and not phone:
            return render_template(
                'index.html',
                error="Please enter a phone number for phone intelligence checks.",
                available_tools=AVAILABLE_TOOLS,
                selected_tools=selected_tools,
                email=email,
                username=username,
                phone=phone
            )

        # All tools now run asynchronously via SSE/AJAX — page renders immediately.
        _write_audit_log(
            "scan_run",
            "success",
            {
                "selected_tools": selected_tools,
                "input_email": bool(email),
                "input_username": bool(username),
                "input_phone": bool(phone),
            }
        )
        _dash_target = email or username or phone
        _log_activity('dashboard', 'search', target_input=_dash_target,
                      metadata={'email': email, 'username': username, 'phone': phone,
                                'tools': selected_tools})

        return render_template(
            'index.html',
            email=email,
            username=username,
            phone=phone,
            police_email=session.get("police_email", ""),
            police_role=session.get("police_role", ""),
            selected_tools=selected_tools,
            available_tools=AVAILABLE_TOOLS,
        )
    return render_template(
        'index.html',
        available_tools=AVAILABLE_TOOLS,
        selected_tools=[],
        email="",
        username="",
        phone="",
        police_email=session.get("police_email", ""),
        police_role=session.get("police_role", "")
    )


@app.route('/tools/<tool_type>', methods=['GET', 'POST'])
def tools_page(tool_type):
    if tool_type == 'email':
        return redirect(url_for('email_intel'))
    if tool_type == 'username':
        return redirect(url_for('username_intel'))
    if tool_type == 'phone':
        return redirect(url_for('phone_intel'))
    return redirect(url_for("index"))


@app.route('/email-intel', methods=['GET', 'POST'])
def email_intel():
    email = ''
    selected_tools = []
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        selected_tools = request.form.getlist('tools')
        if email:
            _log_activity('email_intel', 'search', target_input=email,
                          metadata={'tools': selected_tools})
    else:
        email = request.args.get('email', '').strip()
        selected_tools = request.args.getlist('tools')
    if not selected_tools:
        selected_tools = list(EMAIL_BASED_TOOLS)
    # Strip username/phone tools in case passed wrongly
    selected_tools = [t for t in selected_tools if t in EMAIL_BASED_TOOLS]
    if not selected_tools:
        selected_tools = list(EMAIL_BASED_TOOLS)
    return render_template('email_intel.html', email=email, selected_tools=selected_tools)


@app.route('/username-intel', methods=['GET', 'POST'])
def username_intel():
    username = ''
    selected_tools = []
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        selected_tools = request.form.getlist('tools')
        if username:
            _log_activity('username_intel', 'search', target_input=username,
                          metadata={'tools': selected_tools})
    else:
        username = request.args.get('username', '').strip()
        selected_tools = request.args.getlist('tools')
    valid_username_tools = {"user_scanner", "sherlock", "maigret", "userdeep", "username"}
    if not selected_tools:
        selected_tools = list(valid_username_tools)
    selected_tools = [t for t in selected_tools if t in valid_username_tools]
    if not selected_tools:
        selected_tools = list(valid_username_tools)
    return render_template('username_intel.html', username=username, selected_tools=selected_tools)


@app.route('/phone-intel', methods=['GET', 'POST'])
def phone_intel():
    phone = ''
    if request.method == 'POST':
        phone = request.form.get('phone', '').strip()
        if phone:
            _log_activity('phone_intel', 'search', target_input=phone)
    else:
        phone = request.args.get('phone', '').strip()
    return render_template('phone_intel.html', phone=phone)


@app.route('/api/stream/scan')
def stream_scan():
    """
    Server-Sent Events endpoint for real-time scan results.
    Streams results as they're discovered to avoid user waiting.
    """
    if not _is_authorized():
        return jsonify({"error": "Unauthorized"}), 401
    
    scan_type = request.args.get('type', 'email')
    query = request.args.get('query', '').strip()

    if not query:
        return jsonify({"error": "Query required"}), 400

    _log_activity('user_scanner', 'search', target_input=query,
                  metadata={'scan_type': scan_type})

    def generate():
        try:
            scanner_service = get_scanner_service()
            for event in scanner_service.scan_streaming(scan_type, query):
                yield f"data: {json.dumps(event, ensure_ascii=False)}\n\n"
        except Exception as exc:
            yield f"data: {json.dumps({'type': 'error', 'message': str(exc)})}\n\n"
    
    return Response(
        generate(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no'  # Disable nginx buffering
        }
    )


@app.route('/api/stream/sherlock')
def stream_sherlock():
    """
    Server-Sent Events endpoint for real-time Sherlock scan results.
    """
    if not _is_authorized():
        return jsonify({"error": "Unauthorized"}), 401
    
    username = request.args.get('username', '').strip().lower()
    if not username:
        return jsonify({"error": "Username required"}), 400

    _log_activity('sherlock', 'search', target_input=username)

    def generate():
        found_count = 0
        checked_count = 0
        process = None

        try:
            import importlib.util

            # Always use the venv's Python — never shutil.which which finds system-Python binaries
            if importlib.util.find_spec('sherlock_project') is None:
                yield f"data: {json.dumps({'type': 'error', 'message': 'Sherlock not found. Install: pip install sherlock-project'})}\n\n"
                return
            cmd = [sys.executable, '-u', '-m', 'sherlock_project.sherlock', username, '--print-found', '--no-color']

            env = os.environ.copy()
            env['PYTHONUNBUFFERED'] = '1'
            env['PYTHONIOENCODING'] = 'utf-8'

            # Signal to the frontend that scanning has started
            yield f"data: {json.dumps({'type': 'progress', 'message': 'Sherlock started', 'checked': 0})}\n\n"

            tmpdir = tempfile.mkdtemp()
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                text=True,
                bufsize=1,
                universal_newlines=True,
                cwd=tmpdir,
                env=env
            )

            # Stream stdout line by line — URLs arrive as sherlock finds them
            for line in iter(process.stdout.readline, ''):
                line = line.strip()
                if not line:
                    continue

                urls = re.findall(r'https?://[^\s\]>)]+', line)
                for url in urls:
                    url = url.rstrip('.,;')
                    found_count += 1
                    checked_count += 1
                    yield f"data: {json.dumps({'type': 'result', 'url': url, 'found_count': found_count, 'checked': checked_count})}\n\n"

                if not urls:
                    checked_count += 1
                    if checked_count % 15 == 0:
                        yield f"data: {json.dumps({'type': 'progress', 'checked': checked_count})}\n\n"

            process.stdout.close()
            stderr_out = process.stderr.read().strip()
            process.wait()

            if process.returncode != 0 and found_count == 0 and stderr_out:
                yield f"data: {json.dumps({'type': 'error', 'message': f'Sherlock error (exit {process.returncode}): {stderr_out[:400]}'})}\n\n"
                return

            yield f"data: {json.dumps({'type': 'complete', 'found_count': found_count, 'checked_count': checked_count})}\n\n"

        except GeneratorExit:
            pass
        except Exception as exc:
            yield f"data: {json.dumps({'type': 'error', 'message': f'Sherlock stream error: {str(exc)}'})}\n\n"
        finally:
            if process and process.poll() is None:
                process.kill()
                process.wait()
            shutil.rmtree(tmpdir, ignore_errors=True)
    
    return Response(
        generate(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no'
        }
    )


@app.route('/api/stream/maigret')
def stream_maigret():
    """
    Server-Sent Events endpoint for real-time Maigret scan results.
    """
    if not _is_authorized():
        return jsonify({"error": "Unauthorized"}), 401
    
    username = request.args.get('username', '').strip().lower()
    if not username:
        return jsonify({"error": "Username required"}), 400

    _log_activity('maigret', 'search', target_input=username)

    def generate():
        found_count = 0
        checked_count = 0
        process = None

        try:
            env = os.environ.copy()
            env["PYTHONIOENCODING"] = "utf-8"

            cmd = [sys.executable, "-m", "maigret", username, "--no-color", "--no-progressbar"]

            tmpdir = tempfile.mkdtemp()
            try:
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    stdin=subprocess.DEVNULL,
                    text=True,
                    bufsize=1,
                    universal_newlines=True,
                    cwd=tmpdir,
                    env=env
                )
            except Exception as e:
                yield f"data: {json.dumps({'type': 'error', 'message': f'Maigret failed to start: {str(e)}'})}\n\n"
                return

            # Stream output line by line
            for line in iter(process.stdout.readline, ''):
                line = line.strip()
                if not line:
                    continue

                # Check for URLs in output
                urls = re.findall(r"https?://[^\s)>\]]+", line)
                for url in urls:
                    found_count += 1
                    yield f"data: {json.dumps({'type': 'result', 'url': url, 'found_count': found_count})}\n\n"

                checked_count += 1
                if checked_count % 10 == 0:
                    yield f"data: {json.dumps({'type': 'progress', 'checked': checked_count})}\n\n"

            process.wait()
            yield f"data: {json.dumps({'type': 'complete', 'found_count': found_count})}\n\n"

        except GeneratorExit:
            pass
        finally:
            if process and process.poll() is None:
                process.kill()
                process.wait()
            shutil.rmtree(tmpdir, ignore_errors=True)

    return Response(
        generate(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no'
        }
    )


@app.route('/download/<fmt>')
def download_results(fmt):
    if not _is_authorized():
        return redirect(url_for("login"))

    payload = session.get("last_export")
    if not payload:
        return redirect(url_for("index"))

    if fmt == "json":
        _write_audit_log("download_results", "success", {"format": "json"})
        content = json.dumps(payload, indent=2, ensure_ascii=False)
        return Response(
            content,
            mimetype="application/json",
            headers={"Content-Disposition": "attachment; filename=osint_results.json"}
        )

    if fmt == "csv":
        _write_audit_log("download_results", "success", {"format": "csv"})
        stream = io.StringIO()
        writer = csv.writer(stream)
        writer.writerow(["section", "key", "value"])
        writer.writerow(["meta", "email", payload.get("email", "")])
        writer.writerow(["meta", "username", payload.get("username", "")])
        writer.writerow(["meta", "phone", payload.get("phone", "")])
        writer.writerow(["meta", "selected_tools", ", ".join(payload.get("selected_tools", []))])

        for idx, item in enumerate(payload.get("results", []), start=1):
            writer.writerow([f"holehe_{idx}", "domain", item.get("domain", "")])
            writer.writerow([f"holehe_{idx}", "exists", item.get("exists", "")])
            writer.writerow([f"holehe_{idx}", "emailrecovery", item.get("emailrecovery", "")])
            writer.writerow([f"holehe_{idx}", "phoneNumber", item.get("phoneNumber", "")])
            others = item.get("others", {})
            if isinstance(others, dict):
                for key, value in others.items():
                    writer.writerow([f"holehe_{idx}", f"others.{key}", value])

        for section in ["domain_result", "gravatar_result", "disposable_result", "mx_security_result", "phone_result", "sherlock_result", "maigret_result", "userdeep_result", "whois_result", "email_pivots_result"]:
            value = payload.get(section)
            if isinstance(value, dict):
                for key, val in value.items():
                    writer.writerow([section, key, json.dumps(val, ensure_ascii=False) if isinstance(val, (list, dict)) else val])

        username_result = payload.get("username_result")
        if isinstance(username_result, dict):
            writer.writerow(["username_result", "username", username_result.get("username", "")])
            for platform in username_result.get("platforms", []):
                writer.writerow(["username_result", platform.get("name", ""), platform.get("url", "")])

        csv_data = stream.getvalue()
        stream.close()
        return Response(
            csv_data,
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=osint_results.csv"}
        )

    if fmt == "pdf":
        try:
            from services.pdf_report_service import generate_dashboard_pdf
            pdf_bytes = generate_dashboard_pdf(
                payload,
                officer_email=session.get('police_email', ''),
                officer_role=session.get('police_role', ''),
            )
            _write_audit_log("download_results", "success", {"format": "pdf"})
            return Response(
                pdf_bytes,
                mimetype="application/pdf",
                headers={"Content-Disposition": "attachment; filename=osint_investigation_report.pdf"}
            )
        except Exception as exc:
            import traceback
            print(f"Dashboard PDF Error: {exc}\n{traceback.format_exc()}")
            _write_audit_log("download_results", "error", {"format": "pdf", "error": str(exc)})
            return f"PDF generation failed: {exc}. Try JSON or CSV instead.", 500

    return redirect(url_for("index"))


@app.route('/infra-intel/download/pdf')
def infra_intel_download_pdf():
    if not _is_authorized():
        return redirect(url_for('login'))

    saved = session.get('last_infra_scan')
    if not saved:
        return "No infrastructure scan data available. Run a scan first.", 404

    try:
        from services.pdf_report_service import generate_infra_pdf
        pdf_bytes = generate_infra_pdf(
            saved['result'],
            query=saved.get('query', ''),
            officer_email=session.get('police_email', ''),
            officer_role=session.get('police_role', ''),
        )
        _write_audit_log("download_infra_pdf", "success",
                         {"query": saved.get('query', '')})
        _log_activity('infra_intel', 'export_pdf', target_input=saved.get('query', ''))
        target = saved['result'].get('host_info', {}).get('ip', 'host')
        filename = f"infra_intel_{target.replace('.', '_')}.pdf"
        return Response(
            pdf_bytes,
            mimetype="application/pdf",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
    except Exception as exc:
        import traceback
        print(f"Infra PDF Error: {exc}\n{traceback.format_exc()}")
        _write_audit_log("download_infra_pdf", "error", {"error": str(exc)})
        return f"PDF generation failed: {exc}", 500


@app.route('/ask-ai/download/pdf')
def ask_ai_download_pdf():
    if not _is_authorized():
        return redirect(url_for('login'))

    saved = session.get('last_ask_ai')
    if not saved:
        return "No AI analysis data available. Run an Ask AI query first.", 404

    try:
        from services.pdf_report_service import generate_ask_ai_pdf
        pdf_bytes = generate_ask_ai_pdf(
            saved['query'],
            saved['result'],
            officer_email=session.get('police_email', ''),
            officer_role=session.get('police_role', ''),
        )
        _write_audit_log("download_ask_ai_pdf", "success",
                         {"query_preview": saved['query'][:100]})
        _log_activity('ask_ai', 'export_pdf', target_input=saved['query'][:200])
        return Response(
            pdf_bytes,
            mimetype="application/pdf",
            headers={"Content-Disposition": "attachment; filename=ai_investigation_report.pdf"}
        )
    except Exception as exc:
        import traceback
        print(f"Ask AI PDF Error: {exc}\n{traceback.format_exc()}")
        _write_audit_log("download_ask_ai_pdf", "error", {"error": str(exc)})
        return f"PDF generation failed: {exc}", 500

def run_holehe(email):
    args = Args()
    modules = hc.import_submodules("Sam.modules")
    websites = hc.get_functions(modules, args)
    timeout = args.timeout
    client = httpx.AsyncClient(timeout=timeout)
    out = []

    async def run_checks():
        async with trio.open_nursery() as nursery:
            for website in websites:
                nursery.start_soon(hc.launch_module, website, email, client, out)
        await client.aclose()

    trio.run(run_checks)
    out = sorted(out, key=lambda i: i['name'])
    return out


def run_gravatar_check(email):
    normalized_email = email.strip().lower()
    email_hash = hashlib.md5(normalized_email.encode("utf-8")).hexdigest()
    avatar_url = f"https://www.gravatar.com/avatar/{email_hash}?d=404"
    profile_url = f"https://gravatar.com/{quote(normalized_email)}"

    try:
        response = httpx.get(avatar_url, timeout=8)
        exists = response.status_code == 200
    except Exception:
        exists = False

    return {
        "email_hash": email_hash,
        "avatar_url": avatar_url,
        "profile_url": profile_url,
        "exists": exists
    }


def run_domain_intelligence(email):
    domain = email.split("@")[-1].strip().lower()
    a_records = []
    ip_records = []
    mx_records = []

    try:
        _, _, ip_list = socket.gethostbyname_ex(domain)
        ip_records = sorted(set(ip_list))
    except Exception:
        ip_records = []

    try:
        addr_info = socket.getaddrinfo(domain, None)
        a_records = sorted({entry[4][0] for entry in addr_info if entry and entry[4]})
    except Exception:
        a_records = ip_records

    try:
        proc = subprocess.run(
            ["nslookup", "-type=mx", domain],
            capture_output=True,
            text=True,
            timeout=8
        )
        output = (proc.stdout or "") + "\n" + (proc.stderr or "")
        for line in output.splitlines():
            low = line.lower()
            if "mail exchanger" in low:
                parts = line.split("=")
                if len(parts) > 1:
                    mx_records.append(parts[-1].strip().rstrip("."))
        mx_records = sorted(set([mx for mx in mx_records if mx]))
    except Exception:
        mx_records = []

    return {
        "domain": domain,
        "a_records": a_records,
        "ip_records": ip_records,
        "mx_records": mx_records
    }


def run_username_footprint(username):
    username = username.strip().lower()
    found_platforms = []
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36"
    }
    negative_markers = (
        "not found", "page doesn't exist", "page not found", "sorry, this page isn't available",
        "couldn't find", "404", "does not exist", "not available", "profile not found",
        "blocked", "whoa there, pardner"
    )

    with httpx.Client(headers=headers, follow_redirects=True, timeout=6) as client:
        for platform in USERNAME_PLATFORMS:
            url = platform["url"].format(username=quote(username))
            try:
                response = client.get(url)
                body = response.text.lower()
                final_url = str(response.url).lower()
                is_found = (
                    response.status_code == 200
                    and not any(marker in body for marker in negative_markers)
                    and "404" not in final_url
                    and quote(username).lower() in final_url
                )
                if is_found:
                    found_platforms.append({"name": platform["name"], "url": url})
            except Exception:
                continue

    return {"username": username, "platforms": found_platforms}


def run_disposable_check(email):
    domain = email.split("@")[-1].strip().lower()
    known_disposable_domains = {
        "10minutemail.com", "temp-mail.org", "guerrillamail.com", "mailinator.com",
        "yopmail.com", "sharklasers.com", "tempmail.com", "throwawaymail.com",
        "getnada.com", "moakt.com"
    }
    is_disposable = domain in known_disposable_domains
    risk_level = "High" if is_disposable else "Low"
    return {
        "domain": domain,
        "is_disposable": is_disposable,
        "risk_level": risk_level
    }


def _resolve_txt_records(target):
    records = []
    try:
        proc = subprocess.run(
            ["nslookup", "-type=txt", target],
            capture_output=True,
            text=True,
            timeout=8
        )
        output = (proc.stdout or "") + "\n" + (proc.stderr or "")
        for line in output.splitlines():
            stripped = line.strip()
            if "text =" in stripped.lower():
                parts = stripped.split("=", 1)
                if len(parts) > 1:
                    records.append(parts[1].strip().strip('"'))
        return records
    except Exception:
        return []


def run_mx_security_check(email):
    domain = email.split("@")[-1].strip().lower()
    spf_records = [record for record in _resolve_txt_records(domain) if "v=spf1" in record.lower()]
    dmarc_records = [record for record in _resolve_txt_records(f"_dmarc.{domain}") if "v=dmarc1" in record.lower()]
    return {
        "domain": domain,
        "spf_present": len(spf_records) > 0,
        "dmarc_present": len(dmarc_records) > 0,
        "spf_records": spf_records,
        "dmarc_records": dmarc_records
    }


def run_phone_intelligence(phone):
    phone = phone.strip()
    try:
        parsed = phonenumbers.parse(phone, None if phone.startswith("+") else "IN")
    except Exception:
        return {"input": phone, "valid": False, "error": "Unable to parse phone number."}

    is_valid = phonenumbers.is_valid_number(parsed)
    is_possible = phonenumbers.is_possible_number(parsed)
    e164 = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
    international = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
    national = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)
    region = geocoder.description_for_number(parsed, "en")
    carrier_name = carrier.name_for_number(parsed, "en")
    timezones = list(pn_timezone.time_zones_for_number(parsed))

    num_type = number_type(parsed)
    type_map = {
        PhoneNumberType.MOBILE: "Mobile",
        PhoneNumberType.FIXED_LINE: "Fixed Line",
        PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixed Line or Mobile",
        PhoneNumberType.TOLL_FREE: "Toll Free",
        PhoneNumberType.VOIP: "VoIP",
        PhoneNumberType.PREMIUM_RATE: "Premium Rate",
        PhoneNumberType.UNKNOWN: "Unknown",
    }

    search_links = [
        {"name": "Google Search", "url": f"https://www.google.com/search?q=%22{quote(e164)}%22"},
        {"name": "Bing Search", "url": f"https://www.bing.com/search?q=%22{quote(e164)}%22"},
        {"name": "Truecaller Search", "url": f"https://www.truecaller.com/search/in/{quote(e164.replace('+', ''))}"},
        {"name": "Sync.me Search", "url": f"https://sync.me/search/?number={quote(e164)}"},
    ]

    return {
        "input": phone,
        "valid": is_valid,
        "possible": is_possible,
        "e164": e164,
        "international": international,
        "national": national,
        "region": region or "Unknown",
        "carrier": carrier_name or "Unknown",
        "number_type": type_map.get(num_type, "Other"),
        "timezones": timezones,
        "search_links": search_links,
    }


def run_sherlock_scan(username):
    username = username.strip().lower()
    if not username:
        return {"enabled": False, "error": "Username not provided.", "found_profiles": []}

    result = {
        "enabled": True,
        "installed": False,
        "command": "",
        "found_profiles": [],
        "error": None
    }

    # Try known module entry points across package versions.
    module_candidates = ["sherlock", "sherlock_project.sherlock"]
    for module_name in module_candidates:
        cmd = [sys.executable, "-m", module_name, username, "--print-found", "--no-color"]
        result["command"] = " ".join(cmd)
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
            output = (proc.stdout or "") + "\n" + (proc.stderr or "")
            if f"No module named {module_name.split('.')[0]}" in output:
                continue

            result["installed"] = True
            urls = set(re.findall(r"https?://[^\s)>\]]+", output))
            result["found_profiles"] = sorted(urls)
            if not result["found_profiles"] and proc.returncode != 0:
                result["error"] = "Sherlock ran but no confirmed profiles were returned."
            return result
        except Exception:
            continue

    result["installed"] = False
    result["error"] = "Sherlock is not installed. Run: python -m pip install sherlock-project"
    return result


def run_maigret_scan(username):
    username = username.strip().lower()
    if not username:
        return {"enabled": False, "error": "Username not provided.", "found_profiles": []}

    result = {
        "enabled": True,
        "installed": False,
        "command": "",
        "found_profiles": [],
        "error": None
    }

    # Set environment to handle UTF-8 encoding on Windows
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    
    cmd = [sys.executable, "-m", "maigret", username, "--no-color", "--no-progressbar"]
    result["command"] = " ".join(cmd)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120, env=env)
        output = (proc.stdout or "") + "\n" + (proc.stderr or "")
        # Check specifically for "No module named" error
        if "No module named" in output and "maigret" in output:
            result["installed"] = False
            result["error"] = "Maigret is not installed. Run: python -m pip install maigret"
            return result

        result["installed"] = True
        urls = set(re.findall(r"https?://[^\s)>\]]+", output))
        result["found_profiles"] = sorted(urls)
        if not result["found_profiles"] and proc.returncode != 0:
            result["error"] = "Maigret ran but no confirmed profiles were returned."
        return result
    except Exception as exc:
        result["error"] = f"Maigret execution failed: {exc}"
        return result


def merge_username_deep_results(username, sherlock_result, maigret_result):
    sherlock_profiles = sherlock_result.get("found_profiles", []) if isinstance(sherlock_result, dict) else []
    maigret_profiles = maigret_result.get("found_profiles", []) if isinstance(maigret_result, dict) else []
    merged = sorted(set(sherlock_profiles + maigret_profiles))
    return {
        "username": username,
        "total_profiles": len(merged),
        "profiles": merged,
        "sherlock_installed": bool(isinstance(sherlock_result, dict) and sherlock_result.get("installed")),
        "maigret_installed": bool(isinstance(maigret_result, dict) and maigret_result.get("installed")),
        "sherlock_count": len(sherlock_profiles),
        "maigret_count": len(maigret_profiles),
    }


def run_domain_whois_recon(email):
    domain = email.split("@")[-1].strip().lower()
    whois_text = ""
    ns_records = []
    txt_records = _resolve_txt_records(domain)

    if shutil.which("whois"):
        try:
            proc = subprocess.run(["whois", domain], capture_output=True, text=True, timeout=15)
            whois_text = (proc.stdout or "").strip()
        except Exception:
            whois_text = ""

    # Fallback via nslookup for NS records.
    try:
        proc = subprocess.run(["nslookup", "-type=ns", domain], capture_output=True, text=True, timeout=10)
        output = (proc.stdout or "") + "\n" + (proc.stderr or "")
        for line in output.splitlines():
            if "nameserver" in line.lower() or "nameserver =" in line.lower():
                parts = line.split("=")
                if len(parts) > 1:
                    ns_records.append(parts[-1].strip().rstrip("."))
        ns_records = sorted(set([r for r in ns_records if r]))
    except Exception:
        ns_records = []

    summary = {
        "domain": domain,
        "whois_available": bool(whois_text),
        "whois_preview": whois_text[:1200] if whois_text else "WHOIS command not available on host.",
        "ns_records": ns_records,
        "txt_records": txt_records[:20],
    }
    return summary


def run_email_pivots(email):
    normalized = email.strip().lower()
    quoted = quote(normalized)
    pivots = [
        {"name": "HaveIBeenPwned (manual check)", "url": f"https://haveibeenpwned.com/unifiedsearch/{quoted}"},
        {"name": "DeHashed Search", "url": f"https://www.dehashed.com/search?query={quoted}"},
        {"name": "IntelX Search", "url": f"https://intelx.io/?s={quoted}"},
        {"name": "Google Dork", "url": f"https://www.google.com/search?q=%22{quoted}%22"},
        {"name": "Bing Dork", "url": f"https://www.bing.com/search?q=%22{quoted}%22"},
    ]
    return {"email": normalized, "pivots": pivots}


def run_behindtheemail(email):
    if not BEHINDTHEEMAIL_API_KEY:
        return {"error": "BehindTheEmail API key not configured."}
    try:
        with httpx.Client(timeout=20) as client:
            resp = client.post(
                "https://api.behindtheemail.com/v1/search",
                headers={"Authorization": f"Bearer {BEHINDTHEEMAIL_API_KEY}", "Content-Type": "application/json"},
                json={"email": email.strip().lower()},
            )
        if resp.status_code == 401:
            return {"error": "Invalid BehindTheEmail API key."}
        if resp.status_code == 429:
            return {"error": "BehindTheEmail rate limit reached. Please try again later."}
        if resp.status_code != 200:
            return {"error": f"BehindTheEmail returned HTTP {resp.status_code}."}
        payload = resp.json()
        data = payload.get("data", {})
        status = data.get("status", "unknown")
        profile = data.get("profile", {})
        return {"status": status, "profile": profile}
    except httpx.TimeoutException:
        return {"error": "BehindTheEmail request timed out."}
    except Exception as exc:
        return {"error": f"BehindTheEmail error: {str(exc)}"}


@app.route('/api/results/behindtheemail')
def api_behindtheemail():
    if not _is_authorized():
        return jsonify({"error": "Unauthorized"}), 401
    email = request.args.get('email', '').strip()
    if not email:
        return jsonify({"error": "Email required"}), 400
    result = run_behindtheemail(email)
    return jsonify(result)


@app.route('/api/stream/holehe')
def stream_holehe():
    if not _is_authorized():
        return jsonify({"error": "Unauthorized"}), 401
    email = request.args.get('email', '').strip()
    if not email or not hc.is_email(email):
        return jsonify({"error": "Valid email required"}), 400

    _log_activity('holehe', 'search', target_input=email)

    def generate():
        try:
            yield f"data: {json.dumps({'type': 'progress', 'message': 'Scanning 123 modules…'})}\n\n"
            results = run_holehe(email)
            results = [r for r in results if r['exists']]
            for r in results:
                yield f"data: {json.dumps({'type': 'result', 'data': r})}\n\n"
            yield f"data: {json.dumps({'type': 'complete', 'found_count': len(results)})}\n\n"
        except GeneratorExit:
            pass
        except Exception as exc:
            yield f"data: {json.dumps({'type': 'error', 'message': str(exc)})}\n\n"

    return Response(generate(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})


@app.route('/api/stream/username-footprint')
def stream_username_footprint():
    if not _is_authorized():
        return jsonify({"error": "Unauthorized"}), 401
    username = request.args.get('username', '').strip().lower()
    if not username:
        return jsonify({"error": "Username required"}), 400

    _log_activity('username_footprint', 'search', target_input=username)

    def generate():
        found_count = 0
        headers_ua = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36"
        }
        negative_markers = (
            "not found", "page doesn't exist", "page not found",
            "sorry, this page isn't available", "couldn't find", "404",
            "does not exist", "not available", "profile not found",
            "blocked", "whoa there, pardner"
        )
        try:
            yield f"data: {json.dumps({'type': 'progress', 'checked': 0, 'total': len(USERNAME_PLATFORMS)})}\n\n"
            with httpx.Client(headers=headers_ua, follow_redirects=True, timeout=6) as client:
                for i, platform in enumerate(USERNAME_PLATFORMS):
                    url = platform["url"].format(username=quote(username))
                    try:
                        resp = client.get(url)
                        body = resp.text.lower()
                        final_url = str(resp.url).lower()
                        is_found = (
                            resp.status_code == 200
                            and not any(m in body for m in negative_markers)
                            and "404" not in final_url
                            and quote(username).lower() in final_url
                        )
                        if is_found:
                            found_count += 1
                            yield f"data: {json.dumps({'type': 'result', 'name': platform['name'], 'url': url, 'found_count': found_count})}\n\n"
                    except Exception:
                        pass
                    if (i + 1) % 3 == 0:
                        yield f"data: {json.dumps({'type': 'progress', 'checked': i + 1, 'total': len(USERNAME_PLATFORMS)})}\n\n"
            yield f"data: {json.dumps({'type': 'complete', 'found_count': found_count})}\n\n"
        except GeneratorExit:
            pass
        except Exception as exc:
            yield f"data: {json.dumps({'type': 'error', 'message': str(exc)})}\n\n"

    return Response(generate(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})


@app.route('/api/results/phone')
def api_phone_result():
    if not _is_authorized():
        return jsonify({"error": "Unauthorized"}), 401
    phone = request.args.get('phone', '').strip()
    if not phone:
        return jsonify({"error": "Phone required"}), 400
    _log_activity('phone_intel', 'lookup', target_input=phone)
    return jsonify(run_phone_intelligence(phone))


@app.route('/api/results/disposable')
def api_disposable_result():
    if not _is_authorized():
        return jsonify({"error": "Unauthorized"}), 401
    email_q = request.args.get('email', '').strip()
    if not email_q:
        return jsonify({"error": "Email required"}), 400
    return jsonify(run_disposable_check(email_q))


@app.route('/api/results/email-pivots')
def api_email_pivots_result():
    if not _is_authorized():
        return jsonify({"error": "Unauthorized"}), 401
    email_q = request.args.get('email', '').strip()
    if not email_q:
        return jsonify({"error": "Email required"}), 400
    return jsonify(run_email_pivots(email_q))


# ─── Infrastructure Intel — Shodan-powered module ────────────────────────────

def _resolve_infra_target(raw_input):
    """Parse URL / domain / IP → (resolved_ip, display_target)."""
    target = raw_input.strip()
    if '://' in target:
        target = urlparse(target).hostname or target
    target = target.split('/')[0].split('?')[0].strip()
    if ':' in target and not target.startswith('['):
        target = target.split(':')[0]
    target = re.sub(r'^www\.', '', target)
    parts = target.split('.')
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return target, target
    try:
        ip = socket.gethostbyname(target)
        return ip, target
    except socket.gaierror:
        raise ValueError(f"Could not resolve '{target}' to an IP address.")


def _query_shodan(ip_str):
    """Call Shodan REST API — key stays server-side only."""
    api_key = os.getenv('SHODAN_API_KEY', '')
    if not api_key:
        raise ValueError("SHODAN_API_KEY not set in server environment.")
    resp = httpx.get(
        f"https://api.shodan.io/shodan/host/{ip_str}",
        params={"key": api_key},
        timeout=30
    )
    if resp.status_code == 401:
        raise ValueError("Shodan API key is invalid or expired.")
    if resp.status_code == 404:
        raise ValueError(f"No Shodan data found for {ip_str}. The host may not be indexed yet.")
    if resp.status_code != 200:
        raise ValueError(f"Shodan returned HTTP {resp.status_code}.")
    return resp.json()


def _parse_shodan(host, query, resolved_ip):
    """Normalise raw Shodan JSON into structured intel sections."""
    host_info = {
        "ip":       host.get("ip_str", resolved_ip),
        "query":    query,
        "org":      host.get("org") or "—",
        "isp":      host.get("isp") or "—",
        "asn":      host.get("asn") or "—",
        "country":  host.get("country_name") or "—",
        "country_code": host.get("country_code", ""),
        "city":     host.get("city") or "—",
        "hostnames": host.get("hostnames", []),
        "domains":  host.get("domains", []),
        "tags":     host.get("tags", []),
        "last_update": host.get("last_update", ""),
    }

    geo = {
        "lat": host.get("latitude"),
        "lng": host.get("longitude"),
    }

    services = []
    technologies = {}
    ssl_info = None
    screenshots = []

    for item in host.get("data", []):
        port      = item.get("port")
        transport = item.get("transport", "tcp")
        module    = item.get("_shodan", {}).get("module", "")
        product   = item.get("product", "")
        version   = item.get("version", "")
        cpe       = item.get("cpe23", item.get("cpe", []))
        if isinstance(cpe, str):
            cpe = [cpe]

        services.append({
            "port":      port,
            "transport": transport,
            "service":   module,
            "product":   product,
            "version":   version,
            "cpe":       cpe,
            "banner":    (item.get("data", "") or "")[:300].strip(),
        })

        if product:
            key = product.lower()
            if key not in technologies:
                technologies[key] = {"name": product, "version": version or ""}

        # SSL — take first occurrence
        if "ssl" in item and ssl_info is None:
            ssl_raw  = item["ssl"]
            cert     = ssl_raw.get("cert", {})
            subject  = cert.get("subject", {})
            issuer   = cert.get("issuer", {})

            san_domains = []
            for ext in cert.get("extensions", []):
                if ext.get("name") == "subjectAltName":
                    raw = ext.get("data", "")
                    san_domains = [s.strip().replace("DNS:", "").replace("IP Address:", "")
                                   for s in raw.split(",") if s.strip()]

            tls_vers = [v for v in ssl_raw.get("versions", []) if not v.startswith("-")]

            ssl_info = {
                "subject_cn":  subject.get("CN", ""),
                "issuer_cn":   issuer.get("CN", ""),
                "issuer_org":  issuer.get("O", ""),
                "issued":      cert.get("issued", ""),
                "expires":     cert.get("expires", ""),
                "sha256":      cert.get("fingerprint", {}).get("sha256", ""),
                "san_domains": san_domains[:20],
                "tls_versions": tls_vers,
                "cipher":      ssl_raw.get("cipher", {}).get("name", ""),
            }

        if item.get("screenshot"):
            sc = item["screenshot"]
            if sc.get("data") and len(screenshots) < 3:
                screenshots.append({
                    "data": sc["data"],
                    "mime": sc.get("mime", "image/png"),
                    "port": port,
                })

    services.sort(key=lambda x: x.get("port") or 0)

    vulns = []
    for cve_id, vdata in host.get("vulns", {}).items():
        try:
            cvss = float(vdata.get("cvss", 0) or 0)
        except (TypeError, ValueError):
            cvss = 0.0
        if cvss >= 9.0:
            severity, badge = "Critical", "danger"
        elif cvss >= 7.0:
            severity, badge = "High", "warning"
        elif cvss >= 4.0:
            severity, badge = "Medium", "info"
        else:
            severity, badge = "Low", "secondary"

        vulns.append({
            "cve":      cve_id,
            "cvss":     cvss,
            "severity": severity,
            "badge":    badge,
            "summary":  (vdata.get("summary") or "")[:300],
        })
    vulns.sort(key=lambda x: x["cvss"], reverse=True)

    return {
        "host_info":    host_info,
        "geo":          geo,
        "services":     services,
        "technologies": sorted(technologies.values(), key=lambda t: t["name"].lower()),
        "ssl_info":     ssl_info,
        "vulns":        vulns,
        "screenshots":  screenshots,
        "total_ports":  len(set(s["port"] for s in services if s["port"])),
    }


@app.route('/infra-intel', methods=['GET', 'POST'])
def infra_intel():
    if not _is_authorized():
        return redirect(url_for('login'))

    result         = None
    error          = None
    urlscan_result = None
    urlscan_error  = None
    query          = ""

    if request.method == 'POST':
        query = request.form.get('query', '').strip()
        if not query:
            error = "Please enter a domain, IP address, or URL."
        else:
            resolved_ip    = None
            display_target = None
            try:
                resolved_ip, display_target = _resolve_infra_target(query)
            except ValueError as exc:
                error = str(exc)

            def _run_shodan():
                if resolved_ip is None:
                    raise ValueError(error or "Could not resolve target to an IP address.")
                return _parse_shodan(_query_shodan(resolved_ip), display_target, resolved_ip)

            def _run_urlscan():
                return query_urlscan(query)

            with ThreadPoolExecutor(max_workers=2) as ex:
                f_shodan  = ex.submit(_run_shodan)
                f_urlscan = ex.submit(_run_urlscan)

                try:
                    result = f_shodan.result()
                    session['last_infra_scan'] = {'result': result, 'query': query}
                    error = None
                except Exception as exc:
                    if error is None:
                        error = str(exc)

                try:
                    urlscan_result = f_urlscan.result()
                except Exception as exc:
                    urlscan_error = str(exc)

            _scan_status = "success" if (result or urlscan_result) else "failed"
            _write_audit_log(
                "infra_intel_scan",
                _scan_status,
                {
                    "query":       query,
                    "resolved_ip": resolved_ip,
                    "shodan_ok":   result is not None,
                    "urlscan_ok":  urlscan_result is not None,
                },
            )
            _log_activity('infra_intel', 'search', target_input=query,
                          metadata={'resolved_ip': resolved_ip,
                                    'shodan_ok': result is not None,
                                    'urlscan_ok': urlscan_result is not None},
                          status=_scan_status)

    return render_template(
        'infrastructure_intel.html',
        query=query,
        result=result,
        error=error,
        urlscan_result=urlscan_result,
        urlscan_error=urlscan_error,
        police_email=session.get('police_email', ''),
        police_role=session.get('police_role', ''),
    )


# ─── Ask AI — OpenAI-powered investigation copilot ───────────────────────────

_AI_SYSTEM_PROMPT = (
    "You are an expert OSINT, DFIR, and cybersecurity investigator AI assistant serving law "
    "enforcement at Hyderabad Commissionerate Police (Telangana State Police), India. Guide "
    "investigators in conducting structured, professional open-source intelligence investigations.\n\n"
    "Given an investigation scenario or target, respond with ONLY a valid JSON object — no markdown "
    "fences, no extra text, no comments:\n\n"
    "{\n"
    '  "summary": "2–3 sentence overview of the approach and what intelligence can be gathered",\n'
    '  "tools": [\n'
    "    {\n"
    '      "name": "Tool Name",\n'
    '      "free_paid": "Free" or "Paid" or "Free/Paid",\n'
    '      "input": "What the investigator must provide (e.g. email, username, IP, hash)",\n'
    '      "output": "What intelligence this tool produces",\n'
    '      "url": "https://direct-link-to-tool",\n'
    '      "category": "One of: Username Intelligence, Email Intelligence, Infrastructure Intelligence, '
    'Threat Intelligence, Metadata Analysis, DFIR, Malware Analysis, Reconnaissance"\n'
    "    }\n"
    "  ],\n"
    '  "investigation_flow": ["Step 1: ...", "Step 2: ..."],\n'
    '  "notes": "Legal/ethical caveats or pro tips — empty string if none"\n'
    "}\n\n"
    "Rules:\n"
    "- Output ONLY the raw JSON, nothing else\n"
    "- Include 4–8 relevant tools — quality over quantity\n"
    "- investigation_flow: 4–8 numbered steps\n"
    "- Prefer free tools; include paid only when meaningfully superior\n"
    "- Every URL must be a real, working, direct link to the tool\n"
    "- Tailor all recommendations to a law enforcement context\n"
    "- Focus on open-source, web-accessible tools that require no installation"
)


@app.route('/ask-ai')
def ask_ai():
    if not _is_authorized():
        return redirect(url_for('login'))
    return render_template('ask_ai.html',
                           police_email=session.get('police_email', ''),
                           police_role=session.get('police_role', ''))


@app.route('/api/lens-analyze', methods=['POST'])
def api_lens_analyze():
    """
    Google Lens visual intelligence — registered directly in app.py to
    guarantee route availability regardless of blueprint load order.
    """
    if not _is_authorized():
        return jsonify({"error": "Unauthorized"}), 401

    filepath = session.get('_lens_filepath')
    result   = {"error": "Analysis did not complete."}

    try:
        if not filepath:
            return jsonify({"error": "No image available. Please upload and run EXIF scan first."}), 400
        if not os.path.exists(filepath):
            return jsonify({"error": "Image file no longer available. Please re-upload the image and run the scan again."}), 400

        from services.visual_intelligence_service import VisualIntelligenceService
        result = VisualIntelligenceService().analyze(filepath)
        if 'error' not in result:
            _log_activity('image_intel', 'lens_analyze',
                          target_input=os.path.basename(filepath),
                          metadata={'matches': len(result.get('visual_matches', []))})

    except Exception as exc:
        import traceback as _tb
        print(f"[LensAnalyze] Error: {exc}\n{_tb.format_exc()}")
        result = {"error": f"Visual intelligence failed: {str(exc)[:200]}"}

    # Cleanup temp file
    try:
        if filepath and os.path.exists(filepath):
            os.remove(filepath)
    except OSError:
        pass
    try:
        session.pop('_lens_filepath', None)
        session.modified = True
    except Exception:
        pass

    return jsonify(result)


@app.route('/api/ask-ai', methods=['POST'])
def api_ask_ai():
    if not _is_authorized():
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    query = data.get('query', '').strip()
    if not query:
        return jsonify({"error": "Query is required."}), 400
    if len(query) > 3000:
        return jsonify({"error": "Query too long (max 3000 characters)."}), 400

    api_key = os.getenv('OPENAI_API_KEY', '')
    if not api_key:
        return jsonify({"error": "AI service not configured. Contact your system administrator."}), 503

    try:
        resp = httpx.post(
            'https://api.openai.com/v1/chat/completions',
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={
                "model": "gpt-4o-mini",
                "messages": [
                    {"role": "system", "content": _AI_SYSTEM_PROMPT},
                    {"role": "user", "content": query}
                ],
                "response_format": {"type": "json_object"},
                "temperature": 0.2,
                "max_tokens": 2000
            },
            timeout=30
        )
    except Exception as exc:
        return jsonify({"error": f"AI service unreachable: {str(exc)}"}), 502

    if resp.status_code == 401:
        return jsonify({"error": "AI service authentication failed. Check the API key."}), 502
    if resp.status_code == 429:
        return jsonify({"error": "AI rate limit reached. Please try again in a moment."}), 429
    if resp.status_code != 200:
        return jsonify({"error": f"AI service returned HTTP {resp.status_code}."}), 502

    try:
        content = resp.json()['choices'][0]['message']['content']
        result = json.loads(content)
    except (KeyError, json.JSONDecodeError) as exc:
        return jsonify({"error": f"AI returned an unparseable response: {str(exc)}"}), 502

    session['last_ask_ai'] = {'query': query, 'result': result}
    _write_audit_log("ask_ai", "success", {"query_preview": query[:200]})
    _log_activity('ask_ai', 'query', target_input=query[:500])
    return jsonify(result)


@app.route('/master-prompt')
def master_prompt():
    if not _is_authorized():
        return redirect(url_for('login'))
    return render_template(
        'master_prompt.html',
        police_email=session.get('police_email', ''),
        police_role=session.get('police_role', ''),
    )


@app.route('/api/export/dashboard-pdf', methods=['POST'])
def export_dashboard_pdf():
    """
    Accept collected SSE results as a JSON body from the browser and
    generate a professional PDF report using the shared PDF service.
    Called by the Download PDF Report button on the Main Dashboard.
    """
    if not _is_authorized():
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json(silent=True) or {}

    # Map browser-collected payload to the shape generate_dashboard_pdf() expects
    payload = {
        "email":    data.get("email", ""),
        "username": data.get("username", ""),
        "phone":    data.get("phone", ""),
        "selected_tools": data.get("selected_tools", []),
        # Holehe: list of {domain, exists, emailrecovery, phoneNumber}
        "results": data.get("holehe", []),
        # Other tool results
        "disposable_result":   data.get("disposable_result"),
        "email_pivots_result": data.get("email_pivots_result"),
        "phone_result":        data.get("phone_result"),
        "sherlock_result": {
            "installed": True,
            "found_profiles": data.get("sherlock_profiles", []),
        } if data.get("sherlock_profiles") else None,
        "maigret_result": {
            "installed": True,
            "found_profiles": data.get("maigret_profiles", []),
        } if data.get("maigret_profiles") else None,
        "userdeep_result": {
            "profiles": data.get("userdeep_profiles", []),
        } if data.get("userdeep_profiles") else None,
        "username_result": data.get("username_footprint_result"),
        # User-Scanner found results (email and username modes)
        "user_scanner_email":    data.get("user_scanner_email", []),
        "user_scanner_username": data.get("user_scanner_username", []),
        # BehindTheEmail enrichment
        "behindtheemail_result": data.get("behindtheemail_result"),
    }

    try:
        from services.pdf_report_service import generate_dashboard_pdf
        pdf_bytes = generate_dashboard_pdf(
            payload,
            officer_email=session.get('police_email', ''),
            officer_role=session.get('police_role', ''),
        )
        _write_audit_log("download_dashboard_pdf", "success", {
            "email": data.get("email", ""),
            "username": data.get("username", ""),
        })
        _target = data.get("email") or data.get("username") or data.get("phone") or "unknown"
        _log_activity('dashboard', 'export_pdf', target_input=_target,
                      metadata={'email': data.get('email', ''),
                                'username': data.get('username', '')})
        return Response(
            pdf_bytes,
            mimetype="application/pdf",
            headers={"Content-Disposition": "attachment; filename=osint_dashboard_report.pdf"}
        )
    except Exception as exc:
        import traceback
        print(f"Dashboard PDF export error: {exc}\n{traceback.format_exc()}")
        _write_audit_log("download_dashboard_pdf", "error", {"error": str(exc)})
        return jsonify({"error": f"PDF generation failed: {exc}"}), 500




_AIORNOT_UPLOAD_FOLDER = os.path.join(tempfile.gettempdir(), 'osint_aiornot_uploads')
os.makedirs(_AIORNOT_UPLOAD_FOLDER, exist_ok=True)
_AIORNOT_MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB
_AIORNOT_ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'webp', 'gif', 'mp4', 'mp3'}


def _aiornot_detect_mime(stream):
    """Detect MIME type by reading magic bytes. Returns mime string or None."""
    header = stream.read(16)
    stream.seek(0)
    if header[:3] == b'\xff\xd8\xff':
        return 'image/jpeg'
    if header[:8] == b'\x89PNG\r\n\x1a\n':
        return 'image/png'
    if header[:6] in (b'GIF87a', b'GIF89a'):
        return 'image/gif'
    if header[:4] == b'RIFF' and header[8:12] == b'WEBP':
        return 'image/webp'
    if header[4:8] == b'ftyp' or (len(header) >= 8 and b'ftyp' in header[:8]):
        return 'video/mp4'
    if header[:3] in (b'\xff\xfb', b'\xff\xf3', b'\xff\xf2') or header[:3] == b'ID3':
        return 'audio/mpeg'
    return None


@app.route('/ai-or-not')
def ai_or_not():
    return render_template('ai_or_not.html')



def _conf_pct(val):
    """Convert 0-1 or 0-100 confidence value to a rounded percentage, or None if absent."""
    if val is None:
        return None
    v = float(val)
    return round(v * 100, 1) if v <= 1 else round(v, 1)


def _parse_aiornot_image(data, report, mime_type, filename):
    """Parse image/audio API response schema:
       report.{verdict, ai, human, generator}  +  facets.{nsfw, quality}
    """
    facets = data.get("facets", {})

    verdict = report.get("verdict") or data.get("verdict") or "unknown"

    ai_info = report.get("ai")
    raw_ai = (float(ai_info.get("confidence") or 0) if isinstance(ai_info, dict)
              else float(ai_info) if isinstance(ai_info, (int, float)) else 0.0)
    ai_confidence = _conf_pct(raw_ai)

    human_info = report.get("human")
    if isinstance(human_info, dict):
        raw_human = float(human_info.get("confidence") or 0)
    elif isinstance(human_info, (int, float)):
        raw_human = float(human_info)
    else:
        raw_human = None
    human_confidence = (_conf_pct(raw_human) if raw_human is not None
                        else round(100.0 - ai_confidence, 1))

    generator_raw = report.get("generator") or {}
    generators = {}
    if isinstance(generator_raw, dict):
        for name, val in generator_raw.items():
            try:
                conf = (float(val.get("confidence") or 0) if isinstance(val, dict)
                        else float(val))
                generators[str(name)] = _conf_pct(conf)
            except (TypeError, ValueError):
                pass

    deepfake_data = None
    deepfake_confidence = None
    df_raw = report.get("deepfake")
    if df_raw and isinstance(df_raw, dict):
        df_conf = _conf_pct(float(df_raw.get("confidence") or 0))
        deepfake_confidence = df_conf
        df_rois = []
        for roi in (df_raw.get("rois") or []):
            if isinstance(roi, dict):
                df_rois.append({
                    "is_detected": bool(roi.get("is_detected", True)),
                    "confidence": _conf_pct(float(roi.get("confidence") or 0)),
                    "bbox": roi.get("bbox") or {},
                })
        deepfake_data = {
            "is_detected": bool(df_raw.get("is_detected", False)),
            "confidence": df_conf,
            "roi_count": len(df_rois),
            "rois": df_rois,
        }

    nsfw_data = None
    nsfw_raw = facets.get("nsfw")
    if nsfw_raw and isinstance(nsfw_raw, dict):
        nsfw_data = {"is_detected": bool(nsfw_raw.get("is_detected", False)),
                     "version": nsfw_raw.get("version", "")}

    quality_data = None
    quality_raw = facets.get("quality")
    if quality_raw and isinstance(quality_raw, dict):
        quality_data = {"is_suitable": not bool(quality_raw.get("is_detected", False))}

    reverse_search = None
    rs_raw = report.get("reverse_search") or facets.get("reverse_search")
    if rs_raw and isinstance(rs_raw, dict):
        rs_matches = []
        for m in (rs_raw.get("matches") or []):
            if isinstance(m, dict):
                rs_matches.append({
                    "domain": m.get("domain", ""),
                    "image_url": m.get("image_url", ""),
                    "earliest_crawl_date": m.get("earliest_crawl_date", ""),
                    "earliest_backlink": m.get("earliest_backlink", ""),
                })
        reverse_search = {"was_found": bool(rs_raw.get("was_found", False)),
                          "match_count": len(rs_matches), "matches": rs_matches[:5]}

    meta_data = None
    meta_raw = report.get("meta")
    if meta_raw and isinstance(meta_raw, dict):
        size_bytes = meta_raw.get("size_bytes")
        size_fmt = None
        if size_bytes:
            if size_bytes < 1024:
                size_fmt = f"{size_bytes} B"
            elif size_bytes < 1024 * 1024:
                size_fmt = f"{size_bytes / 1024:.1f} KB"
            else:
                size_fmt = f"{size_bytes / (1024 * 1024):.1f} MB"
        meta_data = {
            "width": meta_raw.get("width"), "height": meta_raw.get("height"),
            "format": meta_raw.get("format"), "size_bytes": size_bytes,
            "size_formatted": size_fmt, "md5": meta_raw.get("md5"),
            "processing_status": meta_raw.get("processing_status") or {},
        }

    return {
        "success": True,
        "verdict": verdict,
        "ai_confidence": ai_confidence,
        "human_confidence": human_confidence,
        "generators": generators,
        "deepfake_confidence": deepfake_confidence,
        "deepfake": deepfake_data,
        "nsfw": nsfw_data,
        "quality": quality_data,
        "reverse_search": reverse_search,
        "meta": meta_data,
        "media_type": (meta_data["format"] if meta_data and meta_data.get("format")
                       else mime_type.split("/")[0]),
        "report_id": data.get("id", ""),
        "created_at": data.get("created_at", ""),
        "filename": filename,
    }


def _parse_aiornot_video(data, report, mime_type, filename):
    """Parse video API v2 response schema:
       report.{ai_video, ai_voice, ai_music, deepfake_video, meta}
    """
    av_raw = report.get("ai_video") or {}
    raw_ai = float(av_raw.get("confidence") or 0) if isinstance(av_raw, dict) else 0.0
    ai_confidence = _conf_pct(raw_ai)
    human_confidence = round(100.0 - ai_confidence, 1)

    ai_detected = bool(av_raw.get("is_detected", False)) if isinstance(av_raw, dict) else (raw_ai >= 0.5)
    verdict = "ai" if ai_detected else "human"

    generators = {}
    voice_raw = report.get("ai_voice")
    if voice_raw and isinstance(voice_raw, dict) and voice_raw.get("confidence") is not None:
        generators["ai_voice"] = _conf_pct(float(voice_raw.get("confidence") or 0))
    music_raw = report.get("ai_music")
    if music_raw and isinstance(music_raw, dict) and music_raw.get("confidence") is not None:
        generators["ai_music"] = _conf_pct(float(music_raw.get("confidence") or 0))

    deepfake_data = None
    deepfake_confidence = None
    dfv_raw = report.get("deepfake_video")
    if dfv_raw and isinstance(dfv_raw, dict):
        df_conf = _conf_pct(float(dfv_raw.get("confidence") or 0))
        deepfake_confidence = df_conf
        deepfake_data = {
            "is_detected": bool(dfv_raw.get("is_detected", False)),
            "confidence": df_conf,
            "roi_count": 0,
            "rois": [],
            "no_faces_found": bool(dfv_raw.get("no_faces_found", False)),
        }

    meta_data = None
    meta_raw = report.get("meta")
    if meta_raw and isinstance(meta_raw, dict):
        size_bytes = meta_raw.get("total_bytes") or meta_raw.get("size_bytes")
        size_fmt = None
        if size_bytes:
            if size_bytes < 1024:
                size_fmt = f"{size_bytes} B"
            elif size_bytes < 1024 * 1024:
                size_fmt = f"{size_bytes / 1024:.1f} KB"
            else:
                size_fmt = f"{size_bytes / (1024 * 1024):.1f} MB"
        proc_status = {}
        if meta_raw.get("audio"):
            proc_status["audio"] = meta_raw["audio"]
        if meta_raw.get("video"):
            proc_status["video"] = meta_raw["video"]
        meta_data = {
            "width": None, "height": None, "format": "MP4",
            "size_bytes": size_bytes, "size_formatted": size_fmt,
            "md5": meta_raw.get("md5"),
            "processing_status": proc_status,
            "duration": meta_raw.get("duration"),
        }

    return {
        "success": True,
        "verdict": verdict,
        "ai_confidence": ai_confidence,
        "human_confidence": human_confidence,
        "generators": generators,
        "deepfake_confidence": deepfake_confidence,
        "deepfake": deepfake_data,
        "nsfw": None,
        "quality": None,
        "reverse_search": None,
        "meta": meta_data,
        "media_type": "video",
        "report_id": data.get("id", ""),
        "created_at": data.get("created_at", ""),
        "filename": filename,
    }


@app.route('/ai-or-not/analyze', methods=['POST'])
@app.route('/premium-tools/ai-or-not/analyze', methods=['POST'])
def ai_or_not_analyze():
    if not _is_authorized():
        return jsonify({"error": "Unauthorized"}), 401

    api_key = os.getenv("AIORNOT_API_KEY")
    if not api_key:
        return jsonify({"error": "AI OR NOT API key not configured. Contact the administrator."}), 503

    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400
    file = request.files['file']
    if not file.filename:
        return jsonify({"error": "No file selected"}), 400

    ext = file.filename.rsplit('.', 1)[-1].lower() if '.' in file.filename else ''
    if ext not in _AIORNOT_ALLOWED_EXTENSIONS:
        return jsonify({"error": f"Unsupported file type. Allowed: JPG, PNG, WEBP, GIF, MP4, MP3"}), 400

    mime_type = _aiornot_detect_mime(file.stream)
    if not mime_type:
        ext_mime = {
            'jpg': 'image/jpeg', 'jpeg': 'image/jpeg', 'png': 'image/png',
            'webp': 'image/webp', 'gif': 'image/gif',
            'mp4': 'video/mp4', 'mp3': 'audio/mpeg',
        }
        mime_type = ext_mime.get(ext)
    if not mime_type:
        return jsonify({"error": "File type not recognised. Please upload a valid image, video, or audio file."}), 400

    if mime_type.startswith('image/'):
        api_endpoint = "https://api.aiornot.com/v1/reports/image"
        form_field   = "object"
        api_timeout  = 60.0
    elif mime_type.startswith('video/'):
        api_endpoint = "https://api.aiornot.com/v2/video/sync"
        form_field   = "video"
        api_timeout  = 120.0
    elif mime_type.startswith('audio/'):
        api_endpoint = "https://api.aiornot.com/v1/reports/audio"
        form_field   = "object"
        api_timeout  = 60.0
    else:
        return jsonify({"error": "Unsupported media type"}), 400

    is_video = mime_type.startswith('video/')

    tmp_path = os.path.join(_AIORNOT_UPLOAD_FOLDER, f"{uuid.uuid4().hex}.{ext}")
    try:
        file.save(tmp_path)
        if os.path.getsize(tmp_path) > _AIORNOT_MAX_FILE_SIZE:
            return jsonify({"error": "File too large (max 50 MB)"}), 400

        with open(tmp_path, 'rb') as fh:
            resp = httpx.post(
                api_endpoint,
                headers={"Authorization": f"Bearer {api_key}"},
                files={form_field: (file.filename, fh, mime_type)},
                timeout=api_timeout,
            )

        if resp.status_code != 200:
            try:
                err_data = resp.json()
                err_msg = err_data.get("message") or err_data.get("error") or f"API error {resp.status_code}"
            except Exception:
                err_msg = f"API request failed (HTTP {resp.status_code})"
            _write_audit_log("ai_or_not_analysis", "error", {"http_status": resp.status_code, "error": err_msg})
            return jsonify({"error": err_msg}), 502

        data = resp.json()

        # ── Debug: log full raw response to server console ──
        try:
            print(f"[AIORNOT DEBUG] FULL RESPONSE: {json.dumps(data, ensure_ascii=False)[:4000]}")
        except Exception as _dbg_exc:
            print(f"[AIORNOT DEBUG] logging error: {_dbg_exc}")

        # Dispatch to modality-specific parser
        report = data.get("report", {})
        if is_video:
            result = _parse_aiornot_video(data, report, mime_type, file.filename)
        else:
            result = _parse_aiornot_image(data, report, mime_type, file.filename)

        _write_audit_log("ai_or_not_analysis", "success", {
            "filename": file.filename,
            "verdict": result.get("verdict"),
            "ai_confidence": result.get("ai_confidence"),
            "deepfake_detected": bool(result.get("deepfake") and result["deepfake"].get("is_detected")),
        })
        _log_activity('ai_or_not', 'analyze', target_input=file.filename,
                      metadata={'verdict': result.get('verdict'),
                                'ai_confidence': result.get('ai_confidence')})
        return jsonify(result)

    except httpx.TimeoutException:
        _write_audit_log("ai_or_not_analysis", "error", {"error": "timeout"})
        return jsonify({"error": "Analysis timed out. Please try again."}), 504
    except httpx.RequestError as exc:
        _write_audit_log("ai_or_not_analysis", "error", {"error": str(exc)})
        return jsonify({"error": f"Network error contacting AI OR NOT API: {exc}"}), 502
    except Exception as exc:
        import traceback
        print(f"AI OR NOT Error: {exc}\n{traceback.format_exc()}")
        _write_audit_log("ai_or_not_analysis", "error", {"error": str(exc)})
        return jsonify({"error": f"Analysis failed: {exc}"}), 500
    finally:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except OSError:
            pass


@app.route('/instagram-sniffer')
def instagram_sniffer():
    if not _is_authorized():
        return redirect(url_for('login'))
    return render_template('instagram_sniffer.html')


@app.route('/api/instagram-sniffer', methods=['POST'])
def api_instagram_sniffer():
    if not _is_authorized():
        return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    username = (data.get('username') or '').strip().lstrip('@')
    if not username:
        return jsonify({"error": "Instagram username is required."}), 400
    _write_audit_log("instagram_sniffer", "start", {"username": username})
    _log_activity('instagram_sniffer', 'search', target_input=username)
    result = run_instagram_sniffer(username)
    status = "error" if "error" in result else "success"
    _write_audit_log("instagram_sniffer", status, {
        "username": username,
        "posts_fetched": result.get("total_posts_fetched", 0),
        "collaborators": len(result.get("all_collaborators", [])),
    })
    return jsonify(result)


@app.route('/api/instagram-image-proxy')
def instagram_image_proxy():
    """Server-side proxy for Instagram CDN thumbnails (bypasses hotlink protection)."""
    if not _is_authorized():
        return '', 401
    url = request.args.get('url', '').strip()
    if not url:
        return '', 400
    # Allow any *.cdninstagram.com or *.fbcdn.net host — block everything else (SSRF guard)
    from urllib.parse import urlparse
    parsed = urlparse(url)
    host = parsed.hostname or ''
    if not (host.endswith('.cdninstagram.com') or host.endswith('.fbcdn.net')):
        return '', 403
    _IG_PROXY_HEADERS = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        ),
        "Referer": "https://www.instagram.com/",
        "Accept": "image/avif,image/webp,image/apng,image/*,*/*;q=0.8",
    }
    try:
        try:
            from curl_cffi.requests import Session as CffiSession
            with CffiSession(impersonate="chrome120") as s:
                resp = s.get(url, headers=_IG_PROXY_HEADERS, timeout=15)
        except ImportError:
            import httpx
            with httpx.Client(timeout=15, follow_redirects=True) as client:
                resp = client.get(url, headers=_IG_PROXY_HEADERS)
        if resp.status_code != 200:
            return '', resp.status_code
        content_type = resp.headers.get('content-type', 'image/jpeg')
        from flask import Response as FlaskResponse
        return FlaskResponse(
            resp.content,
            status=200,
            headers={
                'Content-Type': content_type,
                'Cache-Control': 'public, max-age=3600',
            }
        )
    except Exception:
        return '', 502


if __name__ == '__main__':
    # threaded=True is required so SSE streams (Sherlock, Maigret, user-scanner)
    # do not block concurrent requests from other users.
    app.run(host='0.0.0.0', port=8000, debug=False, threaded=True)
