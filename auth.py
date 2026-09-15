"""Cookie-based authentication for existing users; no public account creation."""
import json
import secrets
import time
from datetime import datetime, timedelta, timezone
from functools import wraps
from urllib.parse import unquote, urlsplit

import click
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, InvalidHashError
from flask import (Blueprint, abort, has_request_context, current_app, flash, jsonify, redirect,
                   render_template, request, session, url_for)
from flask_login import LoginManager, current_user, login_user, logout_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf import FlaskForm
from sqlalchemy import case, or_, update
from sqlalchemy.exc import SQLAlchemyError
from wtforms import PasswordField, StringField
from wtforms.validators import InputRequired, Length

from auth_migration import normalize_identifier
from models import User, db

bp = Blueprint('auth', __name__)
login_manager = LoginManager()
GENERIC_ERROR = 'Invalid username/email or password.'


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def audit(event, uid=None):
    # Structured values; never record login input, credentials, request bodies or tokens.
    current_app.logger.info(json.dumps({'event': event, 'user_id': uid,
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'ip': request.remote_addr if has_request_context() else None}))


def password_policy(password):
    return isinstance(password, str) and 12 <= len(password) <= 128


def set_password(user, password, temporary=True):
    if not password_policy(password):
        raise ValueError('Use a password containing 12 to 128 characters.')
    user.password_hash = current_app.extensions['password_hasher'].hash(password)
    user.password_changed_at = utcnow()
    user.must_change_password = temporary
    user.failed_login_attempts = 0
    user.locked_until = None
    user.auth_token = secrets.token_urlsafe(32)
    user.updated_at = utcnow()


def safe_next(value):
    if not value or len(value) > 2048:
        return url_for('dashboard')
    decoded = value
    for _ in range(4):
        new = unquote(decoded)
        if new == decoded:
            break
        decoded = new
    try:
        parts = urlsplit(decoded)
        valid = (decoded.startswith('/') and not decoded.startswith('//')
                 and not parts.scheme and not parts.netloc and '\\' not in decoded
                 and not any(ord(c) < 32 or ord(c) == 127 for c in decoded)
                 and '%' not in decoded and parts.path not in ('/login', '/logout'))
    except ValueError:
        valid = False
    return value if valid else url_for('dashboard')


class LoginForm(FlaskForm):
    identifier = StringField('Username or email', validators=[InputRequired(), Length(max=256)])
    password = PasswordField('Password', validators=[InputRequired(), Length(max=128)])


class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Current password', validators=[InputRequired(), Length(max=128)])
    new_password = PasswordField('New password', validators=[InputRequired(), Length(min=12, max=128)])
    confirm_password = PasswordField('Confirm new password', validators=[InputRequired(), Length(min=12, max=128)])


def permitted():
    return (current_user.is_authenticated and current_user.role is not None
            and current_user.role.role_name in current_app.config['SOC_ALLOWED_ROLES'])


def soc_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated:
            return unauthorized()
        if current_user.must_change_password:
            if request.path.startswith('/api/'):
                return jsonify(error='Password change required.'), 403
            return redirect(url_for('auth.change_password'))
        if not permitted():
            audit('authorization_denied', current_user.user_id)
            abort(403)
        return view(*args, **kwargs)
    return wrapped


def review_permitted():
    return permitted() and current_user.role.role_name in current_app.config['SOC_REVIEW_ROLES']


def soc_review_required(view):
    @soc_required
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not review_permitted():
            audit('authorization_denied', current_user.user_id)
            abort(403)
        return view(*args, **kwargs)
    return wrapped


@login_manager.unauthorized_handler
def unauthorized():
    if request.path.startswith('/api/'):
        return jsonify(error='Authentication required.'), 401
    return redirect(url_for('auth.login', next=request.path))


@login_manager.user_loader
def load_user(token):
    if not token or len(token) > 128:
        return None
    user = User.query.filter_by(auth_token=token).one_or_none()
    if not user or not user.is_active or user.employment_status != 'Active' or not user.password_hash:
        return None
    now = time.time()
    if (now - session.get('last_activity', 0) > current_app.config['AUTH_IDLE_SECONDS']
            or now - session.get('signed_in_at', 0) > current_app.config['AUTH_MAX_SECONDS']):
        # Revoke the database token so an old cookie cannot restore the session.
        db.session.execute(update(User).where(User.user_id == user.user_id, User.auth_token == token)
                           .values(auth_token=None))
        db.session.commit()
        session.clear()
        return None
    session['last_activity'] = now
    return user


def verify(password, stored_hash):
    hasher = current_app.extensions['password_hasher']
    target = stored_hash or current_app.extensions['dummy_password_hash']
    try:
        valid = hasher.verify(target, password)
    except (VerificationError, InvalidHashError):
        return False
    return bool(stored_hash) and valid


def authenticate(identifier, password):
    now = utcnow()
    rows = User.query.filter(or_(User.login_username == identifier, User.login_email == identifier)).limit(2).all()
    user = rows[0] if len(rows) == 1 else None
    eligible = bool(user and user.is_active and user.employment_status == 'Active'
                    and user.password_hash and (not user.locked_until or user.locked_until <= now))
    valid = verify(password, user.password_hash if eligible else None)
    if not eligible or not valid:
        if eligible:
            # Atomic increment handles concurrent failures without lost updates.
            count = case((User.locked_until.is_not(None), 1), else_=User.failed_login_attempts + 1)
            db.session.execute(update(User).where(User.user_id == user.user_id,
                or_(User.locked_until.is_(None), User.locked_until <= now)).values(
                failed_login_attempts=count,
                locked_until=case((count >= current_app.config['AUTH_MAX_FAILURES'],
                    now + timedelta(seconds=current_app.config['AUTH_LOCK_SECONDS'])), else_=None)))
            db.session.commit()
            db.session.refresh(user)
            if user.locked_until and user.locked_until > now:
                audit('account_locked', user.user_id)
        audit('login_failed', user.user_id if user else None)
        return None
    token = secrets.token_urlsafe(32)
    hasher = current_app.extensions['password_hasher']
    new_hash = hasher.hash(password) if hasher.check_needs_rehash(user.password_hash) else user.password_hash
    # A concurrent reset/login/lockout must not be overwritten by a stale verification.
    result = db.session.execute(update(User).where(User.user_id == user.user_id,
        User.password_hash == user.password_hash, User.auth_token == user.auth_token,
        User.is_active.is_(True), User.employment_status == 'Active',
        or_(User.locked_until.is_(None), User.locked_until <= now)).values(
        auth_token=token, password_hash=new_hash, failed_login_attempts=0,
        locked_until=None, last_login_at=now, updated_at=now))
    db.session.commit()
    if result.rowcount != 1:
        audit('login_failed')
        return None
    db.session.refresh(user)
    return user


def renew_session(user):
    session.clear()
    login_user(user, remember=False, fresh=True)
    session.permanent = True
    session['signed_in_at'] = time.time()
    session['last_activity'] = time.time()


@bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('auth.change_password' if current_user.must_change_password else 'dashboard'))
    form = LoginForm()
    error = None
    if request.method == 'POST':
        if form.validate_on_submit():
            user = authenticate(normalize_identifier(form.identifier.data), form.password.data)
            if user:
                renew_session(user)
                audit('login_success', user.user_id)
                return redirect(url_for('auth.change_password') if user.must_change_password
                                else safe_next(request.args.get('next')))
        else:
            # Same expensive dummy path for bounded but invalid input.
            verify('invalid-form-input', None)
            audit('login_failed')
        error = GENERIC_ERROR
    return render_template('auth/login.html', form=form, error=error), (200 if not error else 401)


@bp.route('/logout', methods=['POST'])
def logout():
    if current_user.is_authenticated:
        uid = current_user.user_id
        db.session.execute(update(User).where(User.user_id == uid, User.auth_token == current_user.auth_token)
                           .values(auth_token=None))
        db.session.commit()
        audit('logout', uid)
    logout_user()
    session.clear()
    return redirect(url_for('auth.login'))


@bp.route('/change-password', methods=['GET', 'POST'])
def change_password():
    if not current_user.is_authenticated:
        return unauthorized()
    form = ChangePasswordForm()
    error = None
    if request.method == 'POST':
        if form.validate_on_submit() and verify(form.current_password.data, current_user.password_hash):
            # Confirmation comparison is transient input only, never an authentication comparison.
            if form.new_password.data != form.confirm_password.data:
                error = 'New passwords do not match.'
            elif verify(form.new_password.data, current_user.password_hash):
                error = 'Choose a different password.'
            else:
                token = current_user.auth_token
                new_hash = current_app.extensions['password_hasher'].hash(form.new_password.data)
                result = db.session.execute(update(User).where(User.user_id == current_user.user_id,
                    User.auth_token == token).values(password_hash=new_hash, auth_token=secrets.token_urlsafe(32),
                    must_change_password=False, password_changed_at=utcnow(), updated_at=utcnow(),
                    failed_login_attempts=0, locked_until=None))
                db.session.commit()
                if result.rowcount != 1:
                    abort(401)
                audit('password_changed', current_user.user_id)
                logout_user()
                session.clear()
                flash('Password updated. Sign in with your new password.', 'success')
                return redirect(url_for('auth.login'))
        else:
            error = 'Unable to change password. Check your current password and use 12 to 128 characters for the new password.'
        audit('password_change_failed', current_user.user_id)
    return render_template('auth/change_password.html', form=form, error=error), (400 if error else 200)


def init_auth(app):
    app.extensions['password_hasher'] = PasswordHasher()
    app.extensions['dummy_password_hash'] = app.extensions['password_hasher'].hash(secrets.token_urlsafe(48))
    login_manager.init_app(app)
    login_manager.session_protection = 'strong'
    limiter = Limiter(key_func=get_remote_address, default_limits=[], app=app)
    app.extensions['auth_limiter'] = limiter
    app.register_blueprint(bp)
    app.view_functions['auth.login'] = limiter.limit('10 per minute;100 per hour', methods=['POST'])(app.view_functions['auth.login'])
    app.view_functions['auth.change_password'] = limiter.limit('5 per minute;30 per hour', methods=['POST'])(app.view_functions['auth.change_password'])
    app.context_processor(lambda: {'soc_permitted': permitted, 'soc_review_permitted': review_permitted})

    @app.before_request
    def enforce_password_change():
        if request.endpoint not in ('static', 'auth.login', 'auth.logout', 'auth.change_password'):
            if current_user.is_authenticated and current_user.must_change_password:
                if request.path.startswith('/api/'):
                    return jsonify(error='Password change required.'), 403
                return redirect(url_for('auth.change_password'))

    @app.cli.group('auth')
    def auth_cli():
        """Manage credentials for existing application users."""

    @auth_cli.command('set-password')
    @click.option('--username', required=True)
    @click.option('--temporary/--permanent', default=True, help='Temporary passwords require change at next login (default).')
    def set_password_cli(username, temporary):
        user = User.query.filter_by(login_username=normalize_identifier(username)).one_or_none()
        if user is None:
            raise click.ClickException('Existing user not found; no user was created.')
        password = click.prompt('New password (12 to 128 characters)', hide_input=True, confirmation_prompt=True)
        try:
            set_password(user, password, temporary)
            db.session.commit()
        except ValueError as exc:
            db.session.rollback()
            raise click.ClickException(str(exc)) from None
        except SQLAlchemyError:
            db.session.rollback()
            audit('password_initialization_failed')
            raise click.ClickException('Unable to update the password; no change was committed.') from None
        finally:
            password = None
        audit('password_initialized', user.user_id)
        click.echo('Password updated successfully.')

    @auth_cli.command('pending')
    def pending_cli():
        """List existing usernames without a password, for local administrators only."""
        for user in User.query.filter(or_(User.password_hash.is_(None), User.password_hash == '')).order_by(User.username):
            click.echo(json.dumps({'username': user.username}, ensure_ascii=True))
