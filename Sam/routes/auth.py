6"""Authentication blueprint — username + password login. No OTP, no signup."""
import json
from datetime import datetime, timezone

import bcrypt
from flask import Blueprint, render_template, request, redirect, url_for, session

from extensions import db

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

_MAX_FAILED_ATTEMPTS = 5
_PW_RULES = [
    (lambda p: len(p) >= 8,                  "Password must be at least 8 characters."),
    (lambda p: any(c.isupper() for c in p),  "Password must contain at least one uppercase letter."),
    (lambda p: any(c.isdigit() for c in p),  "Password must contain at least one number."),
    (lambda p: any(not c.isalnum() for c in p), "Password must contain at least one special character."),
]


# ── Password helpers (bcrypt) ─────────────────────────────────────────────────

def hash_password(plaintext: str) -> str:
    return bcrypt.hashpw(plaintext.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def check_password(plaintext: str, hashed: str) -> bool:
    try:
        # Handle both bcrypt hashes and legacy Werkzeug hashes
        if hashed.startswith('$2b$') or hashed.startswith('$2a$'):
            return bcrypt.checkpw(plaintext.encode('utf-8'), hashed.encode('utf-8'))
        # Werkzeug legacy fallback (scrypt/pbkdf2 — used during transition)
        from werkzeug.security import check_password_hash as _wph
        return _wph(hashed, plaintext)
    except Exception:
        return False


# ── Password validation ───────────────────────────────────────────────────────

def validate_password(pw: str) -> str | None:
    """Return error string or None if valid."""
    for check, msg in _PW_RULES:
        if not check(pw):
            return msg
    return None

_validate_password = validate_password   # alias used by app.py


# ── Session helper ────────────────────────────────────────────────────────────

def set_session(user, remember: bool = False):
    session.permanent = remember
    session['authorized']   = True
    session['user_id']      = user.id
    session['police_email'] = user.username
    session['police_role']  = user.role
    session['full_name']    = user.full_name
    user.last_login = datetime.now(timezone.utc)
    db.session.commit()


# ── Audit log (DB) ────────────────────────────────────────────────────────────

def write_audit(action: str, status: str, user_id: str | None = None,
                details: dict | None = None):
    from models import AuditLog
    entry = AuditLog(
        user_id    = user_id,
        action     = action,
        status     = status,
        ip_address = request.headers.get('X-Forwarded-For', request.remote_addr),
        details    = json.dumps(details or {}, ensure_ascii=False),
    )
    db.session.add(entry)
    db.session.commit()


# ── Routes ────────────────────────────────────────────────────────────────────

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('authorized'):
        return redirect(url_for('index'))

    error = None
    if request.method == 'POST':
        identifier = request.form.get('identifier', '').strip()
        password   = request.form.get('password', '')
        remember   = bool(request.form.get('remember'))

        from models import User
        user = User.query.filter(User.username.ilike(identifier)).first()

        if not user:
            error = "Invalid username or password."
            write_audit('login_failed', 'failed', details={'reason': 'user_not_found', 'identifier': identifier})
        elif user.account_locked:
            error = "Account is locked. Contact your administrator."
            write_audit('login_blocked', 'failed', user_id=user.id, details={'reason': 'account_locked'})
        elif not user.is_active:
            error = "Your account has been disabled. Contact your administrator."
            write_audit('login_blocked', 'failed', user_id=user.id, details={'reason': 'account_disabled'})
        elif not check_password(password, user.password_hash):
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= _MAX_FAILED_ATTEMPTS:
                user.account_locked = True
                db.session.commit()
                error = "Too many failed attempts. Account locked. Contact your administrator."
                write_audit('account_locked', 'failed', user_id=user.id,
                            details={'reason': 'too_many_failed_attempts'})
            else:
                db.session.commit()
                remaining = _MAX_FAILED_ATTEMPTS - user.failed_login_attempts
                error = (f"Invalid username or password. "
                         f"{remaining} attempt{'s' if remaining != 1 else ''} remaining.")
                write_audit('login_failed', 'failed', user_id=user.id,
                            details={'reason': 'wrong_password'})
        else:
            user.failed_login_attempts = 0
            set_session(user, remember)
            write_audit('login', 'success', user_id=user.id)
            return redirect(url_for('index'))

    return render_template('login.html', error=error)


@auth_bp.route('/logout')
def logout():
    user_id = session.get('user_id')
    write_audit('logout', 'success', user_id=user_id)
    session.clear()
    return redirect(url_for('auth.login'))
