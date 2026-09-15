"""SQLAlchemy models for CE-UEBA (Context-Enriched UEBA) POC."""

import sqlite3
from datetime import datetime, timezone
from flask_login import UserMixin
from auth_migration import normalize_identifier

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import event
from sqlalchemy.engine import Engine

db = SQLAlchemy()


@event.listens_for(Engine, "connect")
def _enable_sqlite_foreign_keys(dbapi_connection, connection_record):
    """SQLite disables foreign-key enforcement by default; enable it per connection.
    The isinstance guard keeps this a no-op for non-SQLite engines."""
    if isinstance(dbapi_connection, sqlite3.Connection):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


class Role(db.Model):
    __tablename__ = "roles"

    role_id = db.Column(db.Integer, primary_key=True)
    role_name = db.Column(db.String(80), unique=True, nullable=False)
    clearance_level = db.Column(db.Integer, nullable=False)

    def __repr__(self):  # pragma: no cover - debugging aid
        return f"<Role {self.role_name} clearance={self.clearance_level}>"


class User(UserMixin, db.Model):
    __tablename__ = "users"

    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    full_name = db.Column(db.String(128), nullable=False)
    email = db.Column(db.String(128), unique=True, nullable=False)
    department = db.Column(db.String(64), nullable=False)
    employment_status = db.Column(db.String(32), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey("roles.role_id"))
    previous_role_id = db.Column(db.Integer, db.ForeignKey("roles.role_id"))
    role_change_date = db.Column(db.DateTime)

    password_hash = db.Column(db.Text)
    is_active = db.Column(db.Boolean, nullable=False, default=True, server_default="1")
    must_change_password = db.Column(db.Boolean, nullable=False, default=True, server_default="1")
    failed_login_attempts = db.Column(db.Integer, nullable=False, default=0, server_default="0")
    locked_until = db.Column(db.DateTime)
    last_login_at = db.Column(db.DateTime)
    password_changed_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None),
                           onupdate=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    login_username = db.Column(db.String(256), unique=True)
    login_email = db.Column(db.String(256), unique=True)
    auth_token = db.Column(db.String(128), unique=True)

    def get_id(self):
        return self.auth_token

    # Two FKs to the same table require explicit foreign_keys lists.
    role = db.relationship("Role", foreign_keys=[role_id])
    previous_role = db.relationship("Role", foreign_keys=[previous_role_id])

    def __repr__(self):  # pragma: no cover - debugging aid
        return f"<User {self.username}>"


class ITAsset(db.Model):
    __tablename__ = "it_assets"

    asset_id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(64), unique=True, nullable=False)
    ip_address = db.Column(db.String(45), unique=True, nullable=False)
    criticality_level = db.Column(db.String(16), nullable=False)
    asset_type = db.Column(db.String(64))
    owner_department = db.Column(db.String(64))

    logs = db.relationship("BehavioralLog", backref="asset")
    change_tickets = db.relationship("ChangeTicket", backref="asset")

    def __repr__(self):  # pragma: no cover - debugging aid
        return f"<ITAsset {self.hostname}>"


class ChangeTicket(db.Model):
    __tablename__ = "change_tickets"

    ticket_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.user_id"), nullable=False)
    asset_id = db.Column(db.Integer, db.ForeignKey("it_assets.asset_id"), nullable=False)
    change_type = db.Column(db.String(64), nullable=False)
    approved_start = db.Column(db.DateTime, nullable=False)
    approved_end = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(32), nullable=False)
    description = db.Column(db.Text)

    user = db.relationship("User", backref="change_tickets")


class BehavioralLog(db.Model):
    __tablename__ = "behavioral_logs"

    log_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.user_id"), nullable=False)
    asset_id = db.Column(db.Integer, db.ForeignKey("it_assets.asset_id"), nullable=False)
    event_type = db.Column(db.String(64), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False)
    details = db.Column(db.Text)
    source_ip = db.Column(db.String(45))
    anomaly_type = db.Column(db.String(128))

    user = db.relationship("User", backref="behavioral_logs")
    alert = db.relationship("Alert", backref="log", uselist=False)


class Alert(db.Model):
    __tablename__ = "alerts"

    alert_id = db.Column(db.Integer, primary_key=True)
    log_id = db.Column(db.Integer, db.ForeignKey("behavioral_logs.log_id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.user_id"), nullable=False)
    raw_ml_risk_score = db.Column(db.Float, nullable=False)
    context_adjusted_risk_score = db.Column(db.Float, nullable=False)
    suppression_status = db.Column(db.String(16), nullable=False)
    suppression_reason = db.Column(db.Text)
    severity = db.Column(db.String(16), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False)
    analyst_status = db.Column(db.String(32), nullable=False)
    # JSON-encoded list of contextual factors produced by the risk engine.
    context_factors = db.Column(db.Text)

    user = db.relationship("User", backref="alerts")


@event.listens_for(User, "before_insert")
@event.listens_for(User, "before_update")
def _normalize_login_identifiers(mapper, connection, user):
    if user.is_active is False or user.employment_status != 'Active':
        user.auth_token = None
    user.login_username = normalize_identifier(user.username)
    user.login_email = normalize_identifier(user.email)
    if not user.login_username or not user.login_email or max(len(user.login_username), len(user.login_email)) > 256:
        raise ValueError("Invalid login identifier")
    # Also reject cross-field ambiguity (one employee's email equals another's username).
    conflict = connection.execute(db.select(User.user_id).where(
        db.or_(User.login_username == user.login_email, User.login_email == user.login_username),
        User.user_id != user.user_id if user.user_id is not None else db.true()
    )).first()
    if conflict:
        raise ValueError("Conflicting login identifier")
