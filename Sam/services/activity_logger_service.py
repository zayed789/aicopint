"""Activity logger service — silently records officer tool usage to PostgreSQL.

Call log_activity() from any route. It never raises and never crashes the
caller's request flow — all exceptions are swallowed and warned to the logger.
"""
import json
import logging

_log = logging.getLogger('activity_logger')


def log_activity(
    user_id,
    username,
    full_name,
    tool_name,
    action_type,
    target_input=None,
    metadata=None,
    status='success',
):
    """Write one OfficerActivityLog row.  Safe to call from any request context."""
    try:
        from flask import request as _req
        try:
            ip = _req.headers.get('X-Forwarded-For', _req.remote_addr)
        except RuntimeError:
            ip = None
    except Exception:
        ip = None

    try:
        from extensions import db
        from models import OfficerActivityLog

        extra_str = None
        if metadata:
            try:
                extra_str = json.dumps(metadata, ensure_ascii=False)[:4000]
            except Exception:
                extra_str = None

        entry = OfficerActivityLog(
            user_id      = user_id,
            username     = (username or '')[:50],
            full_name    = (full_name or '')[:100],
            tool_name    = (tool_name or '')[:50],
            action_type  = (action_type or '')[:50],
            target_input = (target_input or '')[:2000] if target_input else None,
            extra_data   = extra_str,
            status       = (status or 'success')[:20],
            ip_address   = (ip or '')[:45] if ip else None,
        )
        db.session.add(entry)
        db.session.commit()
    except Exception as exc:
        try:
            _log.warning('Activity log write failed: %s', exc)
        except Exception:
            pass
