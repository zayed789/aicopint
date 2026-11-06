"""Admin Blueprint — officer management, security monitoring, audit log.

All routes require admin role. Non-admins receive 403.
URL prefix: /admin
"""
import json
import re
from datetime import datetime, timezone, timedelta

from flask import (Blueprint, render_template, request, redirect,
                   url_for, session, abort)
from sqlalchemy import func

from extensions import db
from models import User, AuditLog, OfficerActivityLog
from routes.auth import validate_password, hash_password

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

_USERNAME_RE       = re.compile(r'^[a-zA-Z0-9_.]{1,30}$')
_AUDIT_PAGE_MAX    = 200
_ACTIVITY_PAGE_MAX = 200

_TOOL_LABELS = {
    'dashboard':          'Dashboard',
    'email_intel':        'Email Intel',
    'username_intel':     'Username Intel',
    'phone_intel':        'Phone Intel',
    'infra_intel':        'Infra Intel',
    'ask_ai':             'Ask AI',
    'instagram_sniffer':  'Instagram Sniffer',
    'ai_or_not':          'AI OR NOT',
    'image_intel':        'Image Intel',
    'user_scanner':       'User-Scanner',
    'holehe':             'Holehe',
    'sherlock':           'Sherlock',
    'maigret':            'Maigret',
    'username_footprint': 'Username Footprint',
}


# ── Guards ────────────────────────────────────────────────────────────────────

def _require_admin():
    if not session.get('authorized'):
        return redirect(url_for('auth.login'))
    if session.get('police_role') != 'admin':
        abort(403)
    return None


def _audit(action: str, status: str = 'success', details: dict | None = None):
    entry = AuditLog(
        user_id    = session.get('user_id'),
        action     = action,
        status     = status,
        ip_address = request.headers.get('X-Forwarded-For', request.remote_addr),
        details    = json.dumps(details or {}, ensure_ascii=False),
    )
    db.session.add(entry)
    db.session.commit()


def _admin_count():
    return User.query.filter_by(role='admin', is_active=True).count()


# ── Officer list ──────────────────────────────────────────────────────────────

@admin_bp.route('/officers', methods=['GET'])
def officers():
    redir = _require_admin()
    if redir:
        return redir

    q        = request.args.get('q', '').strip()
    role_f   = request.args.get('role', '').strip()
    status_f = request.args.get('status', '').strip()

    query = User.query
    if q:
        query = query.filter(
            User.username.ilike(f'%{q}%') | User.full_name.ilike(f'%{q}%')
        )
    if role_f:
        query = query.filter_by(role=role_f)
    if status_f == 'active':
        query = query.filter_by(is_active=True, account_locked=False)
    elif status_f == 'inactive':
        query = query.filter_by(is_active=False)
    elif status_f == 'locked':
        query = query.filter_by(account_locked=True)

    all_officers = query.order_by(User.created_at.desc()).all()

    stats = {
        'total':    User.query.count(),
        'active':   User.query.filter_by(is_active=True).count(),
        'locked':   User.query.filter_by(account_locked=True).count(),
        'admins':   User.query.filter_by(role='admin').count(),
        'officers': User.query.filter_by(role='officer').count(),
    }

    return render_template(
        'admin_officers.html',
        officers=all_officers,
        stats=stats,
        q=q, role_f=role_f, status_f=status_f,
        error=request.args.get('error'),
        success=request.args.get('success'),
        police_email=session.get('police_email', ''),
        police_role=session.get('police_role', ''),
    )


# ── Create officer ────────────────────────────────────────────────────────────

@admin_bp.route('/officers/create', methods=['POST'])
def create_officer():
    redir = _require_admin()
    if redir:
        return redir

    full_name = request.form.get('full_name', '').strip()
    username  = request.form.get('username', '').strip()
    password  = request.form.get('password', '')
    role      = request.form.get('role', 'officer').strip()

    def _err(msg):
        return redirect(url_for('admin.officers', error=msg))

    if not full_name:
        return _err("Full name is required.")
    if not username or not _USERNAME_RE.match(username):
        return _err("Username may only contain letters, numbers, dots and underscores (max 30 chars).")
    if role not in ('admin', 'officer'):
        return _err("Role must be 'admin' or 'officer'.")
    pw_err = validate_password(password)
    if pw_err:
        return _err(pw_err)
    if User.query.filter(User.username.ilike(username)).first():
        return _err(f"Username '{username}' is already taken.")

    new_officer = User(
        full_name     = full_name,
        username      = username.lower(),
        password_hash = hash_password(password),
        role          = role,
        is_active     = True,
        created_by    = session.get('user_id'),
    )
    db.session.add(new_officer)
    db.session.commit()
    _audit('create_officer', details={'username': username, 'role': role})
    return redirect(url_for('admin.officers',
                            success=f"Account '{username}' created successfully."))


# ── Edit officer ──────────────────────────────────────────────────────────────

@admin_bp.route('/officers/<officer_id>/edit', methods=['POST'])
def edit_officer(officer_id):
    redir = _require_admin()
    if redir:
        return redir

    officer   = User.query.get_or_404(officer_id)
    full_name = request.form.get('full_name', '').strip()
    username  = request.form.get('username', '').strip()
    role      = request.form.get('role', officer.role).strip()

    def _err(msg):
        return redirect(url_for('admin.officers', error=msg))

    if not full_name:
        return _err("Full name is required.")
    if not username or not _USERNAME_RE.match(username):
        return _err("Username may only contain letters, numbers, dots and underscores.")
    if role not in ('admin', 'officer'):
        return _err("Role must be 'admin' or 'officer'.")
    if officer.role == 'admin' and role != 'admin' and _admin_count() <= 1:
        return _err("Cannot demote the last admin account.")

    existing = User.query.filter(User.username.ilike(username)).first()
    if existing and existing.id != officer.id:
        return _err(f"Username '{username}' is already taken.")

    officer.full_name  = full_name
    officer.username   = username.lower()
    officer.role       = role
    officer.updated_at = datetime.now(timezone.utc)
    db.session.commit()
    _audit('edit_officer', details={'officer_id': officer_id, 'username': username, 'role': role})
    return redirect(url_for('admin.officers', success=f"Account '{username}' updated."))


# ── Reset password ────────────────────────────────────────────────────────────

@admin_bp.route('/officers/<officer_id>/reset-password', methods=['POST'])
def reset_password(officer_id):
    redir = _require_admin()
    if redir:
        return redir

    officer  = User.query.get_or_404(officer_id)
    new_pw   = request.form.get('new_password', '')
    confirm  = request.form.get('confirm_password', '')

    if new_pw != confirm:
        return redirect(url_for('admin.officers', error="Passwords do not match."))
    pw_err = validate_password(new_pw)
    if pw_err:
        return redirect(url_for('admin.officers', error=pw_err))

    officer.password_hash         = hash_password(new_pw)
    officer.failed_login_attempts = 0
    officer.account_locked        = False
    officer.updated_at            = datetime.now(timezone.utc)
    db.session.commit()
    _audit('reset_password', details={'target_officer': officer.username})
    return redirect(url_for('admin.officers',
                            success=f"Password reset for '{officer.username}' and any lock cleared."))


# ── Toggle active ─────────────────────────────────────────────────────────────

@admin_bp.route('/officers/<officer_id>/toggle-active', methods=['POST'])
def toggle_active(officer_id):
    redir = _require_admin()
    if redir:
        return redir

    officer = User.query.get_or_404(officer_id)

    if officer.id == session.get('user_id'):
        return redirect(url_for('admin.officers', error="You cannot disable your own account."))
    if officer.role == 'admin' and officer.is_active and _admin_count() <= 1:
        return redirect(url_for('admin.officers', error="Cannot disable the last admin account."))

    officer.is_active  = not officer.is_active
    officer.updated_at = datetime.now(timezone.utc)
    db.session.commit()
    action = 'enabled' if officer.is_active else 'disabled'
    _audit('toggle_active', details={'target_officer': officer.username, 'action': action})
    return redirect(url_for('admin.officers',
                            success=f"Account '{officer.username}' {action}."))


# ── Unlock account ────────────────────────────────────────────────────────────

@admin_bp.route('/officers/<officer_id>/unlock', methods=['POST'])
def unlock_account(officer_id):
    redir = _require_admin()
    if redir:
        return redir

    officer = User.query.get_or_404(officer_id)
    officer.account_locked        = False
    officer.failed_login_attempts = 0
    officer.updated_at            = datetime.now(timezone.utc)
    db.session.commit()
    _audit('unlock_account', details={'target_officer': officer.username})
    return redirect(url_for('admin.officers',
                            success=f"Account '{officer.username}' unlocked."))


# ── Delete officer ────────────────────────────────────────────────────────────

@admin_bp.route('/officers/<officer_id>/delete', methods=['POST'])
def delete_officer(officer_id):
    redir = _require_admin()
    if redir:
        return redir

    officer = User.query.get_or_404(officer_id)

    if officer.id == session.get('user_id'):
        return redirect(url_for('admin.officers', error="You cannot delete your own account."))
    if officer.role == 'admin' and _admin_count() <= 1:
        return redirect(url_for('admin.officers', error="Cannot delete the last admin account."))

    username = officer.username
    # Nullify audit log foreign keys before delete to preserve audit history
    AuditLog.query.filter_by(user_id=officer.id).update({'user_id': None})
    db.session.delete(officer)
    db.session.commit()
    _audit('delete_officer', details={'deleted_officer': username})
    return redirect(url_for('admin.officers', success=f"Account '{username}' deleted."))


# ── Login history ─────────────────────────────────────────────────────────────

@admin_bp.route('/login-history')
def login_history():
    redir = _require_admin()
    if redir:
        return redir

    login_actions = {'login', 'login_failed', 'login_blocked', 'account_locked', 'logout'}
    events = (AuditLog.query
              .filter(AuditLog.action.in_(login_actions))
              .order_by(AuditLog.timestamp.desc())
              .limit(_AUDIT_PAGE_MAX)
              .all())

    # Attach username for display
    user_cache = {}
    rows = []
    for e in events:
        if e.user_id and e.user_id not in user_cache:
            u = User.query.get(e.user_id)
            user_cache[e.user_id] = u.username if u else '(deleted)'
        rows.append({
            'timestamp': e.timestamp,
            'action':    e.action,
            'status':    e.status,
            'username':  user_cache.get(e.user_id, '—'),
            'ip':        e.ip_address or '—',
            'details':   json.loads(e.details) if e.details else {},
        })

    return render_template(
        'admin_login_history.html',
        events=rows,
        police_email=session.get('police_email', ''),
        police_role=session.get('police_role', ''),
    )


# ── Officer activity log ──────────────────────────────────────────────────────

@admin_bp.route('/officers/<officer_id>/activity')
def officer_activity(officer_id):
    redir = _require_admin()
    if redir:
        return redir

    officer = User.query.get_or_404(officer_id)

    # ── Filters from query params ──────────────────────────────────────────────
    tool_f   = request.args.get('tool', '').strip()
    status_f = request.args.get('status', '').strip()
    search_f = request.args.get('q', '').strip()
    date_from_s = request.args.get('date_from', '').strip()
    date_to_s   = request.args.get('date_to', '').strip()

    q = OfficerActivityLog.query.filter_by(user_id=officer_id)

    if tool_f:
        q = q.filter_by(tool_name=tool_f)
    if status_f:
        q = q.filter_by(status=status_f)
    if search_f:
        q = q.filter(OfficerActivityLog.target_input.ilike(f'%{search_f}%'))
    if date_from_s:
        try:
            dt_from = datetime.strptime(date_from_s, '%Y-%m-%d').replace(tzinfo=timezone.utc)
            q = q.filter(OfficerActivityLog.timestamp >= dt_from)
        except ValueError:
            pass
    if date_to_s:
        try:
            dt_to = (datetime.strptime(date_to_s, '%Y-%m-%d').replace(tzinfo=timezone.utc)
                     + timedelta(days=1))
            q = q.filter(OfficerActivityLog.timestamp < dt_to)
        except ValueError:
            pass

    logs = q.order_by(OfficerActivityLog.timestamp.desc()).limit(_ACTIVITY_PAGE_MAX).all()

    # ── Summary stats ──────────────────────────────────────────────────────────
    total_searches = OfficerActivityLog.query.filter_by(user_id=officer_id).count()
    failed_count   = OfficerActivityLog.query.filter_by(
        user_id=officer_id, status='failed').count()

    last_entry = (OfficerActivityLog.query
                  .filter_by(user_id=officer_id)
                  .order_by(OfficerActivityLog.timestamp.desc())
                  .first())
    last_active = last_entry.timestamp if last_entry else None

    most_used_row = (db.session.query(
            OfficerActivityLog.tool_name,
            func.count(OfficerActivityLog.id).label('cnt'))
        .filter(OfficerActivityLog.user_id == officer_id)
        .group_by(OfficerActivityLog.tool_name)
        .order_by(func.count(OfficerActivityLog.id).desc())
        .first())
    most_used_tool = (
        _TOOL_LABELS.get(most_used_row.tool_name, most_used_row.tool_name)
        if most_used_row else '—'
    )

    # Distinct tool names for filter dropdown
    tool_names = [r[0] for r in
                  db.session.query(OfficerActivityLog.tool_name)
                  .filter_by(user_id=officer_id)
                  .distinct()
                  .order_by(OfficerActivityLog.tool_name)
                  .all()]

    return render_template(
        'officer_activity.html',
        officer        = officer,
        logs           = logs,
        total_searches = total_searches,
        failed_count   = failed_count,
        last_active    = last_active,
        most_used_tool = most_used_tool,
        tool_labels    = _TOOL_LABELS,
        tool_names     = tool_names,
        tool_f         = tool_f,
        status_f       = status_f,
        search_f       = search_f,
        date_from_s    = date_from_s,
        date_to_s      = date_to_s,
        police_email   = session.get('police_email', ''),
        police_role    = session.get('police_role', ''),
    )


# ── Redirect legacy /admin/users to /admin/officers ───────────────────────────

@admin_bp.route('/users')
@admin_bp.route('/users/<path:subpath>', methods=['GET', 'POST'])
def redirect_legacy_users(subpath=''):
    return redirect(url_for('admin.officers'), 301)
