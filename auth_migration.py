"""Additive SQLite authentication migration. No application import or table rebuild."""
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
import uuid

# Fixed SQL only: no identifiers or clauses originate from user input.
COLUMNS = {
    'password_hash': 'ALTER TABLE users ADD COLUMN password_hash TEXT',
    'is_active': 'ALTER TABLE users ADD COLUMN is_active BOOLEAN NOT NULL DEFAULT 1',
    'must_change_password': 'ALTER TABLE users ADD COLUMN must_change_password BOOLEAN NOT NULL DEFAULT 1',
    'failed_login_attempts': 'ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER NOT NULL DEFAULT 0',
    'locked_until': 'ALTER TABLE users ADD COLUMN locked_until DATETIME',
    'last_login_at': 'ALTER TABLE users ADD COLUMN last_login_at DATETIME',
    'password_changed_at': 'ALTER TABLE users ADD COLUMN password_changed_at DATETIME',
    'created_at': 'ALTER TABLE users ADD COLUMN created_at DATETIME',
    'updated_at': 'ALTER TABLE users ADD COLUMN updated_at DATETIME',
    'login_username': 'ALTER TABLE users ADD COLUMN login_username VARCHAR(256)',
    'login_email': 'ALTER TABLE users ADD COLUMN login_email VARCHAR(256)',
    'auth_token': 'ALTER TABLE users ADD COLUMN auth_token VARCHAR(128)',
}

def normalize_identifier(value):
    return value.strip().casefold()


def migrate_database(path):
    path = Path(path).resolve()
    if not path.is_file():
        raise ValueError('Database does not exist; migration never creates a replacement database.')
    source = sqlite3.connect(path, timeout=30)
    backup = None
    try:
        source.execute('BEGIN IMMEDIATE')
        rows = source.execute('SELECT user_id, username, email FROM users').fetchall()
        seen = {}
        conflicts = set()
        for uid, username, email in rows:
            for raw in (username, email):
                key = normalize_identifier(raw or '')
                if not key or len(key) > 256:
                    raise ValueError(f'Invalid login identifier on user ID {uid}; no changes made.')
                if key in seen and seen[key] != uid:
                    conflicts.update((uid, seen[key]))
                seen[key] = uid
        if conflicts:
            raise ValueError('Duplicate normalized login identifiers on user IDs: '
                             + ', '.join(map(str, sorted(conflicts))) + '. No changes made.')
        folder = path.parent / 'auth_backups'
        folder.mkdir(mode=0o700, exist_ok=True)
        backup = folder / (path.name + '.' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')
                           + '.' + uuid.uuid4().hex[:8] + '.bak')
        fd = os.open(backup, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        # Separate reader while BEGIN IMMEDIATE prevents concurrent writers.
        with sqlite3.connect(path) as reader, sqlite3.connect(backup) as target:
            reader.backup(target)
        present = {r[1] for r in source.execute('PRAGMA table_info(users)')}
        for name, statement in COLUMNS.items():
            if name not in present:
                source.execute(statement)
        now = datetime.now(timezone.utc).replace(tzinfo=None).isoformat(' ')
        for uid, username, email in rows:
            source.execute('UPDATE users SET login_username=?, login_email=?, '
                           'created_at=COALESCE(created_at, ?), updated_at=COALESCE(updated_at, ?) '
                           'WHERE user_id=?',
                           (normalize_identifier(username), normalize_identifier(email), now, now, uid))
        source.execute('CREATE UNIQUE INDEX IF NOT EXISTS ux_users_login_username ON users(login_username)')
        source.execute('CREATE UNIQUE INDEX IF NOT EXISTS ux_users_login_email ON users(login_email)')
        source.execute('CREATE UNIQUE INDEX IF NOT EXISTS ux_users_auth_token ON users(auth_token)')
        source.execute("""CREATE TRIGGER IF NOT EXISTS auth_identifier_insert
            BEFORE INSERT ON users WHEN EXISTS (SELECT 1 FROM users WHERE
            login_username=NEW.login_email OR login_email=NEW.login_username)
            BEGIN SELECT RAISE(ABORT, 'Conflicting login identifier'); END""")
        source.execute("""CREATE TRIGGER IF NOT EXISTS auth_identifier_update
            BEFORE UPDATE OF login_username,login_email ON users WHEN EXISTS
            (SELECT 1 FROM users WHERE user_id!=NEW.user_id AND
            (login_username=NEW.login_email OR login_email=NEW.login_username))
            BEGIN SELECT RAISE(ABORT, 'Conflicting login identifier'); END""")
        source.commit()
        return backup, len(rows)
    except Exception:
        source.rollback()
        raise
    finally:
        source.close()

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database', required=True)
    args = parser.parse_args()
    try:
        backup, count = migrate_database(args.database)
    except (ValueError, sqlite3.Error) as exc:
        # SQLite error text may contain SQL or paths; never print it.
        parser.exit(1, (str(exc) if isinstance(exc, ValueError) else 'Database migration failed; transaction rolled back.') + '\n')
    print(f'Authentication migration complete. Preserved {count} users. Backup: {backup}')
