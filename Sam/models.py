"""SQLAlchemy models — Phase 11: officer/admin auth, bcrypt, DB audit log."""
import json
import uuid
from datetime import datetime, timezone
from extensions import db


def _uid():
    return str(uuid.uuid4())


def _now():
    return datetime.now(timezone.utc)


class User(db.Model):
    __tablename__ = 'users'

    id                    = db.Column(db.String(36), primary_key=True, default=_uid)
    full_name             = db.Column(db.String(100), nullable=False)
    username              = db.Column(db.String(50), unique=True, nullable=False, index=True)
    password_hash         = db.Column(db.String(255), nullable=False)
    role                  = db.Column(db.String(20), default='officer', nullable=False)
    is_active             = db.Column(db.Boolean, default=True, nullable=False)
    created_by            = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=True)
    created_at            = db.Column(db.DateTime(timezone=True), nullable=False, default=_now)
    updated_at            = db.Column(db.DateTime(timezone=True), nullable=False, default=_now, onupdate=_now)
    last_login            = db.Column(db.DateTime(timezone=True), nullable=True)
    failed_login_attempts = db.Column(db.Integer, default=0, nullable=False)
    account_locked        = db.Column(db.Boolean, default=False, nullable=False)

    created_by_user = db.relationship('User', remote_side='User.id', foreign_keys=[created_by])
    audit_logs      = db.relationship('AuditLog', backref='officer', lazy=True,
                                      foreign_keys='AuditLog.user_id')

    __table_args__ = (
        db.Index('ix_users_role_active', 'role', 'is_active'),
    )

    def to_dict(self):
        return {
            'id':             self.id,
            'full_name':      self.full_name,
            'username':       self.username,
            'role':           self.role,
            'is_active':      self.is_active,
            'account_locked': self.account_locked,
            'last_login':     self.last_login.isoformat() if self.last_login else None,
        }


class AuditLog(db.Model):
    __tablename__ = 'audit_logs'

    id         = db.Column(db.String(36), primary_key=True, default=_uid)
    user_id    = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=True)
    action     = db.Column(db.String(50), nullable=False)
    status     = db.Column(db.String(20), nullable=False, default='success')
    ip_address = db.Column(db.String(45), nullable=True)
    details    = db.Column(db.Text, nullable=True)   # JSON string
    timestamp  = db.Column(db.DateTime(timezone=True), nullable=False, default=_now, index=True)

    __table_args__ = (
        db.Index('ix_audit_user_timestamp', 'user_id', 'timestamp'),
        db.Index('ix_audit_action',         'action'),
    )


class OfficerActivityLog(db.Model):
    __tablename__ = 'officer_activity_logs'

    id           = db.Column(db.String(36), primary_key=True, default=_uid)
    user_id      = db.Column(db.String(36), db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    username     = db.Column(db.String(50), nullable=False, default='')
    full_name    = db.Column(db.String(100), nullable=False, default='')
    tool_name    = db.Column(db.String(50), nullable=False)
    action_type  = db.Column(db.String(50), nullable=False)
    target_input = db.Column(db.Text, nullable=True)
    extra_data   = db.Column(db.Text, nullable=True)   # JSON string (named extra_data — 'metadata' is reserved by SQLAlchemy)
    status       = db.Column(db.String(20), nullable=False, default='success')
    ip_address   = db.Column(db.String(45), nullable=True)
    timestamp    = db.Column(db.DateTime(timezone=True), nullable=False, default=_now, index=True)

    __table_args__ = (
        db.Index('ix_activity_user_timestamp', 'user_id', 'timestamp'),
        db.Index('ix_activity_tool_timestamp', 'tool_name', 'timestamp'),
    )

    def to_dict(self):
        return {
            'id':           self.id,
            'user_id':      self.user_id,
            'username':     self.username,
            'full_name':    self.full_name,
            'tool_name':    self.tool_name,
            'action_type':  self.action_type,
            'target_input': self.target_input,
            'extra_data':   json.loads(self.extra_data) if self.extra_data else {},
            'status':       self.status,
            'ip_address':   self.ip_address,
            'timestamp':    self.timestamp.isoformat() if self.timestamp else None,
        }
