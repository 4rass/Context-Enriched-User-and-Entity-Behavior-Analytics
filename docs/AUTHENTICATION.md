# CE-UEBA authentication and administrator guide

Authentication uses the existing `users` records in the configured database.
There is no second user table, public registration route, default password, or
preconfigured account. The checked-in seed generator is synthetic demonstration
content; authentication does not call it or create replacement users.

## Architecture and changes

The existing application uses `create_app`, Flask-SQLAlchemy models, SQLite,
Jinja templates, and Flask-WTF CSRF protection. The original job roles and
clearance levels describe employee context, not permission to operate a SOC.
Access is therefore explicitly granted to existing role names by configuration.

| File | Responsibility |
|---|---|
| `auth.py` | Flask-Login, Argon2id, forms, authentication routes, authorization, rate limiting, password CLI, security events |
| `auth_migration.py` | Standalone additive SQLite migration, conflict detection, transaction and backup |
| `models.py` | Authentication fields and normalized identifiers on the existing User model |
| `app.py` | Configuration, protected routes, error handling, optional trusted proxy support, lazy WSGI application |
| `templates/auth/login.html` | Accessible sign-in form |
| `templates/auth/change_password.html` | Current-password verification and required password change |
| `templates/auth/unavailable.html` | Database-independent error response |
| `templates/base.html` | Sign-in, password change, and CSRF-protected sign-out navigation |
| `templates/alert_details.html` | Read-only display when the account lacks review permission |
| `static/js/auth.js` | Show/hide control and duplicate-submit prevention; no browser credential storage |
| `static/css/style.css` | Responsive authentication styling in the existing palette |
| `pyproject.toml`, `uv.lock`, `requirements.txt` | Flask-Login, Flask-Limiter with Redis support, and argon2-cffi |
| `tests/test_auth.py` | Authentication, migration, session, role, error, and concurrency regressions |
| `tests/test_app.py` | Existing functionality checked using a genuinely authenticated test client |

`README.md` and existing diagrams were intentionally left unchanged. Their
pre-authentication descriptions and original ERD no longer describe these new
security fields; this guide documents the extension.

## Install and migrate on macOS

Stop the running Flask server with Ctrl+C. Work in the directory containing
`app.py`, `models.py`, and `pyproject.toml` (the root of a GitHub clone, or
`ce_ueba_flask_app` in the original delivery).

With uv:

```bash
uv sync --locked
uv run python auth_migration.py --database instance/ce_ueba.db
```

Without uv:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python auth_migration.py --database instance/ce_ueba.db
```

For another SQLite database, supply its exact path to `--database` and configure
`CE_UEBA_DATABASE_URI` to reference the same database. The migration is SQLite-only.
It refuses nonexistent files rather than creating a substitute database.
Do not run `seed_data.py` to initialize authentication on an existing dataset.

The migration obtains a SQLite write reservation, checks every existing username
and email for normalized duplicates and cross-field collisions, and creates a
consistent backup using SQLite's backup API. Backups are stored beneath the
original database directory in `auth_backups`, with directory mode 0700 and file
mode 0600 on POSIX. For the default database this is already ignored by Git.
For custom database locations, exclude that database and its backups from Git too.

It then adds missing columns, backfills normalized identifiers and migration-time
metadata, creates unique indexes, and commits. It never drops or reconstructs the
users table. Conflicts report only the affected internal user IDs to the local
administrator; resolve them against authoritative identity records and rerun.
Any migration error rolls back the schema/data transaction. Each repeat run
creates another backup; existing password hashes and security state are preserved.
`created_at` for historical users is the migration time, not a fabricated original
account creation time. New users created through the ORM use their creation time.

The local database was migrated during implementation after backup. Re-running
this command is safe. All 12 original user records and all original values in
all six application tables were compared with the backup and remained unchanged.
No passwords were initialized during implementation.

### Added fields

| Field | Meaning |
|---|---|
| `password_hash` | Nullable Argon2id hash; NULL/empty cannot authenticate |
| `is_active` | Administrative account enablement; employment must also be exactly Active |
| `must_change_password` | Defaults true; temporary credentials cannot access application data |
| `failed_login_attempts`, `locked_until` | Atomic failure counter and temporary lockout expiry |
| `last_login_at`, `password_changed_at` | UTC login and credential timestamps |
| `created_at`, `updated_at` | UTC account metadata |
| `login_username`, `login_email` | Trimmed, Unicode-casefolded identifiers, each uniquely indexed |
| `auth_token` | Random, revocable Flask-Login identifier; unique when present |

Identity changes must go through the ORM normalization hooks. Migration also
installs cross-field collision triggers. Do not use raw SQL to change username or
email without updating and checking the normalized fields. On fresh databases,
ORM hooks and unique indexes enforce these rules; run the migration after creating
an empty schema if cross-field database triggers are needed before external writes.

## Initialize an existing user's password

List accounts that have no password, from the administrator's terminal:

```bash
uv run --active flask --app app:create_app auth pending
```

Choose an existing username from that output, then replace `USERNAME` below:

```bash
uv run --active flask --app app:create_app auth set-password --username USERNAME

\\❯ uv run --active flask --app app:create_app auth set-password --username zeynep.arslan
[2026-09-16 00:48:04,412] WARNING in app: Using an ephemeral development signing key; sessions expire on restart.
New password (12 to 128 characters): 
Repeat for confirmation: 
[2026-09-16 00:48:12,230] INFO in auth: {"event": "password_initialized", "user_id": 9, "timestamp": "2026-09-15T21:48:12.230218+00:00", "ip": null}
Password updated successfully

# Restart Flask with --active placed before python
FLASK_DEBUG=1 uv run --active python app.py
```

The terminal prompts twice with hidden input. Enter a unique password or passphrase
of 12 to 128 characters. Spaces and special characters are allowed; input is not
trimmed or truncated. Do not put the password on the command line, in this guide,
or in any configuration file. The CLI refuses to create an unknown user.

The default is a temporary password: the user must change it at first sign-in.
When the account owner chooses their own final password directly through the
hidden administrative terminal prompt, the administrator can deliberately use:

```bash
uv run flask --app app:create_app auth set-password --username USERNAME --permanent
```

For standard Python, replace `uv run flask` with `python -m flask` in these commands
with `.venv` activated. The command resets failure/lock fields and revokes old
sessions. It does not activate disabled employees or grant SOC permissions.
Transfer any temporary password through an approved private channel, never Git,
shared documents, or application logs. Password recovery is administrator-assisted;
there is no unauthenticated web reset endpoint.

## Configure role permissions and run locally

Both role allowlists default to empty. A high clearance does not automatically
grant console access. Select roles according to your organization's actual policy.
For example, to explicitly approve the existing IT Administrator role for reading
SOC data and submitting analyst reviews:

```bash
export CE_UEBA_SOC_ROLES='IT Administrator'
export CE_UEBA_SOC_REVIEW_ROLES='IT Administrator'
export CE_UEBA_ENV=development
export CE_UEBA_SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"
uv run python app.py

// or run
CE_UEBA_SOC_ROLES='IT Administrator' CE_UEBA_SOC_REVIEW_ROLES='IT Administrator' CE_UEBA_ENV=development CE_UEBA_SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')" uv run python app.py
```

These assignments grant permission to every active, password-initialized account
with that existing role. They are examples for the administrator to choose; the
implementation did not apply these grants to the local environment. Comma-separated
role names allow multiple roles. Review permission also requires console-read
permission. Users without an approved role receive HTTP 403 after authentication.

Open **http://127.0.0.1:5001/login**. Sign in with the initialized username or email.
Complete the required password change, then sign in again with the new password.
Sign out through the navigation button (POST with CSRF); GET cannot log out.
Stop the server with Ctrl+C when finished. Standard Python users run `python app.py`.

The example signing-key command passes a generated secret into the environment
without printing its value. It lasts for that shell session. Use a secure secret
manager for persistent deployments. An absent development key generates an
unlogged ephemeral key and invalidates sessions after process restart; independent
workers must share a configured signing key.

## Session and authentication behavior

- Flask-Login loads the real user from the database on each authenticated request.
  Cookies contain a revocable random user token and minimum session metadata,
  not passwords, hashes, email addresses, or role claims.
- Login clears the old session, rotates the database token, and issues fresh
  signed session state. Only one active login per account is supported: signing
  in elsewhere invalidates the older session.
- Logout and password initialization/reset/change revoke old tokens. ORM account
  deactivation or non-Active employment also revokes the token. Role permissions
  are checked server-side on every request.
- Idle expiry is 30 minutes; absolute sign-in lifetime is 8 hours. Authenticated
  requests refresh the signed activity timestamp. Expiry revokes the database token.
  Idle tracking measures requests, not keyboard activity; an active stolen session
  remains a risk until revocation or absolute expiry.
- Five consecutive password failures cause a 15-minute lockout. Attempts while
  locked do not extend the lock. After expiry the next failure starts a new count;
  a successful login clears it. Atomic updates prevent lost concurrent increments.
- Login accepts up to 10 POSTs/minute and 100/hour per IP. Password changes accept
  5/minute and 30/hour. Local limits use in-process memory; production requires a
  shared backend. These limits complement account lockout, not replace it.
- Unknown, disabled, suspended, locked, uninitialized, and wrong-password logins
  use the same message. Missing/ineligible users take a dummy Argon2 verification
  path. Similar processing reduces enumeration signals but is not constant-time.
- Only local `next` paths are accepted. External URLs, protocol-relative paths,
  backslashes, control characters, malformed URLs, and encoded bypasses fall back
  to the dashboard.
- Passwords exist transiently in process memory only to validate input, compare
  confirmation input, and call the maintained hashing library. They are never
  persisted, logged, sent back, or compared with a stored plaintext credential.
  Python cannot guarantee zeroization of immutable strings in process memory.

## Production configuration

Production hardening is implemented, but deployment security still depends on TLS,
proxy isolation, secrets, database permissions, and operational monitoring. Do not
publish the Flask development server as a production service.

| Setting | Development | Production |
|---|---|---|
| `CE_UEBA_ENV` | `development` | `production` |
| `CE_UEBA_SECRET_KEY` | Shared random environment key recommended; ephemeral fallback | Required, at least 32 cryptographically random characters |
| `CE_UEBA_RATE_STORAGE` | `memory://` | Shared Redis URI or another supported shared backend |
| Session cookie | HttpOnly, SameSite=Lax; Secure off for local HTTP | HttpOnly, SameSite=Lax, Secure required |
| `FLASK_DEBUG` | Optional local debugging | Rejected when enabled |
| `CE_UEBA_PROXY_HOPS` | `0` | Exact trusted proxy count, only after network/proxy restrictions |

Set environment variables through the deployment secret/configuration manager.
With TLS terminated at a single trusted reverse proxy, `CE_UEBA_PROXY_HOPS=1`
allows Werkzeug ProxyFix to read the final forwarded IP and scheme. Set this only
if direct access to the application is blocked and that proxy overwrites forwarded
headers. The default ignores all forwarded headers. Forwarded host, port, and
prefix are not trusted. Incorrect proxy trust permits IP spoofing and limiter
bypass; leaving trust disabled behind a proxy groups clients into the proxy's IP
bucket instead.

HSTS (`max-age=31536000`) is emitted only for secure requests in production; configure
TLS before enabling production. Existing CSP, frame protection, nosniff, referrer
policy, and no-store behavior remain. No new third-party browser assets were added.
The existing Bootstrap/CDN dependency still applies.

An example WSGI invocation after configuring TLS proxying, permissions, environment
secrets, shared Redis, and an appropriate process count:

```bash
uv run --with gunicorn gunicorn --bind 127.0.0.1:8000 'app:create_app()'
```

Gunicorn is an optional deployment dependency, not required for the local demo.
Size worker concurrency for Argon2 memory/CPU use. Defaults are argon2-cffi's
Argon2id parameters (currently 64 MiB, time cost 3, parallelism 4), with a new salt
per hash. Successful sign-in upgrades outdated parameters. Existing non-Argon2 or
corrupt hashes fail closed and require administrator reset; this application had
no pre-existing password hashes to migrate.

Flask config additionally exposes `AUTH_MAX_FAILURES`, `AUTH_LOCK_SECONDS`,
`AUTH_IDLE_SECONDS`, `AUTH_MAX_SECONDS`, and `PERMANENT_SESSION_LIFETIME` for a
reviewed deployment configuration. Keep cookie and server lifetime policies aligned.

Security events are JSON-encoded at INFO level: login success/failure, lockout,
logout, initialization/reset, password change, and authorization denial. They include
UTC time, internal user ID when available, and request IP. User-entered identifiers,
passwords, hashes, cookies, CSRF tokens, secret keys, and request bodies are excluded.
Database errors log only their exception type. Route database failures return a
generic 503 page without invoking the user lookup again. Configure a protected log
sink, retention, alerting, and redaction in upstream infrastructure; never enable
request-body or cookie logging for authentication endpoints.

## Rollback without destroying current data

1. Stop all application workers and writers. Keep the affected service unavailable
   while evaluating rollback; an earlier version may expose unauthenticated routes.
2. Preserve the current database and backup directory. Record the backup path printed
   by the migration and verify it is from immediately before the intended migration.
3. For a code-only rollback, the new columns can remain: older SQLAlchemy models
   ignore additional columns. Do not drop the users table or auth columns automatically.
4. If a database rollback is necessary, restore the backup into a **different** file
   and point `CE_UEBA_DATABASE_URI` at it. The example below refuses to overwrite an
   existing destination and uses SQLite's backup API:

```bash
python3 - <<'PY'
import os
import sqlite3
from pathlib import Path
source = Path(input('Exact pre-migration backup path: ')).expanduser().resolve(strict=True)
target = Path('instance/ce_ueba_rollback.db').resolve()
fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
os.close(fd)
with sqlite3.connect(source.as_uri() + '?mode=ro', uri=True) as src, sqlite3.connect(target) as dst:
    src.backup(dst)
print('Rollback copy created. The current database has not been overwritten.')
PY
```

5. Use the matching previous application revision in an isolated checkout and set
   `CE_UEBA_DATABASE_URI` to the absolute SQLite URI for `ce_ueba_rollback.db`.
   Review user counts, alert counts, and sample records before reopening local access.
   Do not run the new auth code against a pre-auth schema without migrating it again.
6. The rollback copy does not contain changes made after the backup, including new
   reviews or passwords. Keep the current database for reconciliation. Rotate the
   signing key before resuming service. No restore or destructive rollback is automated.

## Verification and limits

Run the full isolated suite:

```bash
uv run pytest -q
# Or, inside the activated virtual environment:
python -m pytest -q
```

Latest verification: **76 tests passed**. The suite reports 11 pre-existing
`datetime.utcnow()` deprecation warnings in the seed/risk modules. Python compilation,
JavaScript syntax, and Git whitespace checks also passed.

Tests use temporary SQLite databases. Importing `app` no longer creates the default
application/database; lazy `app:application` remains compatible with WSGI/Flask CLI.

| Requirement | Verification |
|---|---|
| Existing-user login; normalized username/email | Automated login and identity normalization tests |
| Incorrect, unknown, inactive, suspended, missing-hash and locked accounts | Generic response tests |
| Hashing, verification, rehashing and password boundaries | Argon2 and CLI policy tests |
| Lockout, expiry, successful reset and concurrent increments | Account lockout/concurrency tests |
| Protected pages/API and least-privilege role checks | Anonymous, allowed-role, denied-role and read-only-role tests |
| Logout/reset/change revocation and one-session policy | Copied-cookie, reset and second-login tests |
| Required password change and current-password confirmation | Forced-change and rejection tests |
| CSRF, SQL injection and redirect defenses | CSRF-enabled endpoint tests and malicious identifier/path cases |
| Migration backup, duplicates, transaction rollback and idempotency | Legacy-database migration tests |
| Production fail-closed configuration, cookies and HSTS | HTTPS test-client configuration tests |
| Database errors and sensitive log suppression | Injected-failure and log-content tests |
| Existing application behavior | Original application/risk/review regressions with authenticated clients |
| Original database preservation | Compared every original field/row in all six tables with the backup |
| JavaScript syntax | `node --check static/js/auth.js` |

The implementation does not include MFA, self-service recovery, a persistent
security-event audit table, or a production deployment. Live Redis/TLS/proxy
integration and visual keyboard/mobile browser QA remain deployment checks; no
browser was available in this session. The templates provide labels, autocomplete,
focus styles, live status/error regions, password toggles and responsive layout,
but these are not a substitute for an accessibility audit.

## Design references

- [Flask-Login sessions and alternative identifiers](https://flask-login.readthedocs.io/en/latest/)
- [Argon2 password hashing and rehash checks](https://argon2-cffi.readthedocs.io/en/stable/)
- [Flask-Limiter shared storage configuration](https://flask-limiter.readthedocs.io/en/stable/configuration.html)
