"""
Development startup script for the OSINT Investigation Platform.

Usage (from within the Sam/ directory):
    python start_server.py

For production, use gunicorn instead:
    gunicorn -w 4 --threads 4 -b 0.0.0.0:8000 app:app

Environment variables (set before running, or place in a .env file):
    APP_SECRET_KEY          - Strong random secret (REQUIRED in production)
    POLICE_PORTAL_PASSWORD  - Default admin fallback password
    POLICE_ALLOWED_DOMAINS  - Comma-separated allowed email domains
    POLICE_BRAND_LOGO_PATH  - Absolute path to police emblem PNG (optional)
    POLICE_AUDIT_LOG_PATH   - Path to audit log file (default: audit_logs/police_portal_audit.jsonl)
    POLICE_USERS_FILE       - Path to user accounts JSON (default: data/police_users.json)
"""

import os
import sys

# Resolve and set the working directory to the Sam/ app root regardless
# of where this script is invoked from.
APP_DIR = os.path.dirname(os.path.abspath(__file__))
os.chdir(APP_DIR)
sys.path.insert(0, APP_DIR)

# Warn if critical env vars are missing rather than silently using weak defaults.
if not os.environ.get("APP_SECRET_KEY"):
    print("[WARNING] APP_SECRET_KEY not set — using insecure default. Set this env var before production use.")

if not os.environ.get("POLICE_PORTAL_PASSWORD"):
    print("[WARNING] POLICE_PORTAL_PASSWORD not set — admin fallback password is 'ChangeMe@123'. Change it.")

from app import app

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    print(f"[OSINT Portal] Starting on http://0.0.0.0:{port}")
    print(f"[OSINT Portal] Python: {sys.executable}")
    print(f"[OSINT Portal] Working dir: {APP_DIR}")
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
