"""Authentication regressions run only on temporary databases with CSRF enabled."""
import hashlib
import re
import secrets
import sqlite3
import time
from datetime import timedelta
from pathlib import Path

import pytest
from argon2 import PasswordHasher
from sqlalchemy.exc import OperationalError

from app import create_app
from auth import GENERIC_ERROR, set_password, utcnow
from auth_migration import migrate_database
from models import User, Role, db


@pytest.fixture
def app(tmp_path):
    app = create_app({'TESTING': True, 'SECRET_KEY': secrets.token_urlsafe(48),
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///' + str(tmp_path/'test.db'),
        'SOC_ALLOWED_ROLES': {'SOC Analyst'}, 'SOC_REVIEW_ROLES': {'SOC Analyst'}, 'RATELIMIT_ENABLED': False})
    app.config['TEST_PASSWORD'] = secrets.token_urlsafe(24)
    with app.app_context():
        role = Role(role_name='SOC Analyst', clearance_level=3)
        user = User(username='existing.employee', email='employee@example.test', full_name='Existing Employee',
                    department='Security', employment_status='Active', role=role)
        db.session.add(user)
        set_password(user, app.config['TEST_PASSWORD'], temporary=False)
        db.session.commit()
    yield app
    with app.app_context():
        db.session.remove()
        db.engine.dispose()


@pytest.fixture
def client(app):
    return app.test_client()


def csrf(client, path='/login'):
    response=client.get(path)
    match=re.search(rb'name="csrf_token"[^>]*value="([^"]+)"',response.data)
    assert match, response.data[:200]
    return match.group(1).decode()


def login(client,app,identifier='existing.employee',password=None,next=''):
    return client.post('/login'+next, data={'identifier':identifier,
        'password':app.config['TEST_PASSWORD'] if password is None else password,
        'csrf_token':csrf(client)})


def modify(app,**fields):
    with app.app_context():
        user=User.query.one()
        for k,v in fields.items():setattr(user,k,v)
        db.session.commit()


def test_login_email_normalization_and_session(app,client):
    assert login(client,app,identifier='  EMPLOYEE@EXAMPLE.TEST ').status_code==302
    assert client.get('/dashboard').status_code==200
    with client.session_transaction() as s:
        assert '_user_id' in s and 'password_hash' not in s and 'password' not in s
        assert app.config['TEST_PASSWORD'] not in str(dict(s))
    with app.app_context():assert User.query.one().last_login_at is not None


@pytest.mark.parametrize('state',['wrong','unknown','inactive','suspended','missing','locked','injection'])
def test_generic_failure(app,client,state):
    identifier='existing.employee'; password=app.config['TEST_PASSWORD']
    if state=='wrong':password=secrets.token_urlsafe(24)
    if state=='unknown':identifier='unknown'
    if state=='inactive':modify(app,is_active=False)
    if state=='suspended':modify(app,employment_status='Suspended')
    if state=='missing':modify(app,password_hash=None)
    if state=='locked':modify(app,locked_until=utcnow()+timedelta(minutes=15))
    if state=='injection':identifier="' OR 1=1 --"
    r=login(client,app,identifier,password)
    assert r.status_code==401 and GENERIC_ERROR.encode() in r.data
    assert client.get('/api/dashboard-data').status_code==401


def test_lockout_and_expiration(app,client):
    for _ in range(5):assert login(client,app,password='wrong-password-value').status_code==401
    with app.app_context():
        u=User.query.one(); assert u.failed_login_attempts==5 and u.locked_until>utcnow()
        until=u.locked_until
    assert login(client,app).status_code==401
    with app.app_context():assert User.query.one().locked_until==until
    modify(app,locked_until=utcnow()-timedelta(seconds=1))
    assert login(client,app).status_code==302
    with app.app_context():assert User.query.one().failed_login_attempts==0 and User.query.one().locked_until is None


def test_failures_reset(app,client):
    login(client,app,password='wrong-password-value')
    assert login(client,app).status_code==302
    with app.app_context():assert User.query.one().failed_login_attempts==0


@pytest.mark.parametrize('path',['/dashboard','/users','/user/1','/alert/1'])
def test_protected_route(client,path):
    r=client.get(path);assert r.status_code==302 and '/login?' in r.location


def test_logout_revokes_copied_cookie(app,client):
    login(client,app)
    token=csrf(client,'/change-password')
    old=client.get_cookie('session').value
    assert client.get('/logout').status_code==405
    assert client.post('/logout',data={'csrf_token':token}).status_code==302
    client.set_cookie('session',old)
    assert client.get('/api/dashboard-data').status_code==401


@pytest.mark.parametrize('path',['/login','/logout','/change-password','/alerts/1/review'])
def test_csrf_rejection(client,path):
    assert client.post(path,data={'identifier':'existing.employee','password':'invalid'}).status_code==400


@pytest.mark.parametrize('destination',['https://evil.test','//evil.test','/\\evil.test','/%2f%2fevil.test','/%0devil','javascript:alert(1)','http://[broken','/%252f%252fevil.test'])
def test_unsafe_redirect(app,client,destination):
    from urllib.parse import urlencode
    r=login(client,app,next='?'+urlencode({'next':destination}))
    assert r.location=='/dashboard'


def test_safe_redirect(app,client):
    assert login(client,app,next='?next=/users').location=='/users'


def test_password_hash_and_rehash(app,client):
    with app.app_context():
        u=User.query.one()
        assert u.password_hash.startswith('$argon2id$')
        assert PasswordHasher().verify(u.password_hash,app.config['TEST_PASSWORD'])
        u.password_hash=PasswordHasher(time_cost=1,memory_cost=8192,parallelism=1).hash(app.config['TEST_PASSWORD'])
        db.session.commit()
    assert login(client,app).status_code==302
    with app.app_context():assert not PasswordHasher().check_needs_rehash(User.query.one().password_hash)


def test_cli_initialization_and_no_creation(app):
    modify(app,password_hash=None,failed_login_attempts=5,locked_until=utcnow()+timedelta(minutes=15))
    password=secrets.token_urlsafe(24)
    runner=app.test_cli_runner()
    result=runner.invoke(args=['auth','set-password','--username','existing.employee'],input=password+'\n'+password+'\n')
    assert result.exit_code==0,result.output
    assert password not in result.output and '$argon2' not in result.output
    with app.app_context():
        u=User.query.one();assert u.must_change_password and u.failed_login_attempts==0 and u.locked_until is None
        assert PasswordHasher().verify(u.password_hash,password)
    result=runner.invoke(args=['auth','set-password','--username','missing'])
    assert result.exit_code!=0
    with app.app_context():assert User.query.count()==1


def test_pending_cli(app):
    modify(app,password_hash=None)
    result=app.test_cli_runner().invoke(args=['auth','pending'])
    assert 'existing.employee' in result.output and '$argon2' not in result.output


def test_role_authorization(app,client):
    app.config['SOC_ALLOWED_ROLES']=set()
    assert login(client,app).status_code==302
    for path in ['/dashboard','/users','/user/1','/alert/1','/api/dashboard-data']:
        assert client.get(path).status_code==403
    token=csrf(client,'/change-password')
    assert client.post('/alerts/1/review',data={'csrf_token':token,'analyst_status':'Open'}).status_code==403


def test_temporary_password_flow(app,client):
    modify(app,must_change_password=True)
    assert login(client,app).location=='/change-password'
    assert client.get('/dashboard').location=='/change-password'
    assert client.get('/api/dashboard-data').status_code==403
    old=client.get_cookie('session').value
    new=secrets.token_urlsafe(24)
    r=client.post('/change-password',data={'csrf_token':csrf(client,'/change-password'),
        'current_password':app.config['TEST_PASSWORD'],'new_password':new,'confirm_password':new})
    assert r.status_code==302
    client.set_cookie('session',old)
    assert client.get('/api/dashboard-data').status_code==401
    assert login(client,app,password=new).location=='/dashboard'
    with app.app_context():assert not User.query.one().must_change_password


@pytest.mark.parametrize('length',[0,11,129])
def test_password_policy_cli(app,length):
    password='x'*length
    result=app.test_cli_runner().invoke(args=['auth','set-password','--username','existing.employee'],input=password+'\n'+password+'\n')
    assert result.exit_code!=0


def test_password_spaces_preserved(app,client):
    password='  '+secrets.token_urlsafe(24)+'  '
    with app.app_context():
        set_password(User.query.one(),password,False);db.session.commit()
    assert login(client,app,password=password.strip()).status_code==401
    assert login(client,app,password=password).status_code==302


@pytest.mark.parametrize('field',['last_activity','signed_in_at'])
def test_session_expiration(app,client,field):
    login(client,app)
    with client.session_transaction() as s:s[field]=time.time()-40000
    assert client.get('/api/dashboard-data').status_code==401


def test_reset_revokes_session(app,client):
    login(client,app)
    with app.app_context():set_password(User.query.one(),secrets.token_urlsafe(24));db.session.commit()
    assert client.get('/api/dashboard-data').status_code==401


def test_deactivation_revokes_access(app,client):
    login(client,app);modify(app,is_active=False)
    assert client.get('/api/dashboard-data').status_code==401


def test_ip_rate_limit(tmp_path):
    app=create_app({'TESTING':True,'SQLALCHEMY_DATABASE_URI':'sqlite:///'+str(tmp_path/'rate.db')})
    c=app.test_client()
    for _ in range(10):assert login(c,app,password='wrong-password-value').status_code==401
    assert login(c,app,password='wrong-password-value').status_code==429


def test_production_configuration(tmp_path):
    base={'APP_ENV':'production','SQLALCHEMY_DATABASE_URI':'sqlite:///'+str(tmp_path/'prod.db'),
          'SECRET_KEY':None}
    with pytest.raises(RuntimeError):create_app(base)
    base['SECRET_KEY']=secrets.token_urlsafe(48)
    with pytest.raises(RuntimeError):create_app(base)
    base['RATELIMIT_STORAGE_URI']='redis://localhost:6379/0';base['SESSION_COOKIE_SECURE']=True
    app=create_app(base)
    r=app.test_client().get('/login',base_url='https://localhost')
    cookie=r.headers['Set-Cookie']
    assert 'Secure' in cookie and 'HttpOnly' in cookie and 'SameSite=Lax' in cookie
    assert 'Strict-Transport-Security' in r.headers


def test_login_page_does_not_echo_password(app,client):
    password=secrets.token_urlsafe(24)
    r=login(client,app,password=password)
    assert password.encode() not in r.data
    assert b'autocomplete="current-password"' in r.data
    assert b'autocomplete="username"' in r.data


def old_database(path,duplicate=False):
    with sqlite3.connect(path) as c:
        c.execute('CREATE TABLE users(user_id INTEGER PRIMARY KEY,username TEXT,email TEXT,employment_status TEXT)')
        c.execute('INSERT INTO users VALUES(1,?,?,?)',('Alice','alice@example.test','Active'))
        if duplicate:c.execute('INSERT INTO users VALUES(2,?,?,?)',(' ALICE ','other@example.test','Active'))
        c.execute('CREATE TABLE unrelated(id INTEGER PRIMARY KEY,value TEXT)')
        c.execute("INSERT INTO unrelated VALUES(1,'preserve me')")


def test_migration_backup_preservation_and_repeatability(tmp_path):
    path=tmp_path/'legacy.db';old_database(path)
    backup,count=migrate_database(path)
    assert count==1 and backup.exists()
    with sqlite3.connect(backup) as c:assert 'password_hash' not in {r[1] for r in c.execute('PRAGMA table_info(users)')}
    with sqlite3.connect(path) as c:
        assert c.execute('SELECT username,email,employment_status FROM users').fetchone()==('Alice','alice@example.test','Active')
        assert c.execute('SELECT value FROM unrelated').fetchone()[0]=='preserve me'
        assert c.execute('SELECT password_hash,must_change_password FROM users').fetchone()==(None,1)
    migrate_database(path)
    with sqlite3.connect(path) as c:assert c.execute('SELECT count(*) FROM users').fetchone()[0]==1


def test_migration_duplicate_detection_no_mutation(tmp_path):
    path=tmp_path/'legacy.db';old_database(path,True)
    before=path.read_bytes()
    with pytest.raises(ValueError,match='Duplicate'):migrate_database(path)
    assert before==path.read_bytes()


def test_migration_cross_identifier_detection(tmp_path):
    path=tmp_path/'legacy.db';old_database(path)
    with sqlite3.connect(path) as c:c.execute("INSERT INTO users VALUES(2,'another','ALICE','Active')")
    with pytest.raises(ValueError,match='Duplicate'):migrate_database(path)


def test_uniqueness(app):
    with app.app_context():
        db.session.add(User(username=' EXISTING.EMPLOYEE ',email='another@example.test',full_name='Other',department='X',employment_status='Active'))
        with pytest.raises(Exception):db.session.commit()
        db.session.rollback()


def test_concurrent_failures_lock_account(app):
    from concurrent.futures import ThreadPoolExecutor
    from auth import authenticate
    def fail(_):
        with app.app_context():
            assert authenticate('existing.employee','wrong-password-value') is None
    with ThreadPoolExecutor(max_workers=5) as pool:
        list(pool.map(fail, range(5)))
    with app.app_context():
        user=User.query.one()
        assert user.failed_login_attempts==5 and user.locked_until>utcnow()


def test_database_error_is_generic(app,client,monkeypatch):
    token=csrf(client)
    import auth
    def failure(*args):
        raise OperationalError('SENSITIVE SQL',{},Exception('SENSITIVE DATABASE PATH'))
    monkeypatch.setattr(auth,'authenticate',failure)
    r=client.post('/login',data={'csrf_token':token,'identifier':'existing.employee','password':app.config['TEST_PASSWORD']})
    assert r.status_code==503
    assert b'SENSITIVE' not in r.data and app.config['TEST_PASSWORD'].encode() not in r.data


def test_database_failure_loading_session_is_generic(app,client,monkeypatch):
    login(client,app)
    from sqlalchemy.orm import Query
    def failure(*args,**kwargs):
        raise OperationalError('SENSITIVE SQL',{},Exception('SENSITIVE PATH'))
    monkeypatch.setattr(Query,'one_or_none',failure)
    r=client.get('/dashboard')
    assert r.status_code==503 and b'SENSITIVE' not in r.data


def test_deactivation_reactivation_does_not_restore_old_session(app,client):
    login(client,app)
    old=client.get_cookie('session').value
    modify(app,is_active=False)
    modify(app,is_active=True)
    client.set_cookie('session',old)
    assert client.get('/api/dashboard-data').status_code==401


def test_second_login_revokes_first_session(app,client):
    login(client,app)
    other=app.test_client()
    login(other,app)
    assert client.get('/api/dashboard-data').status_code==401
    assert other.get('/api/dashboard-data').status_code==200


def test_security_logs_do_not_contain_credentials(app,client,caplog):
    password=app.config['TEST_PASSWORD']
    login(client,app)
    with app.app_context():stored_hash=User.query.one().password_hash
    assert 'login_success' in caplog.text
    assert password not in caplog.text and stored_hash not in caplog.text


def test_old_schema_requires_explicit_migration(tmp_path):
    path=tmp_path/'old.db';old_database(path)
    with pytest.raises(RuntimeError,match='migration required'):
        create_app({'SQLALCHEMY_DATABASE_URI':'sqlite:///'+str(path)})
    with sqlite3.connect(path) as c:
        assert 'password_hash' not in {r[1] for r in c.execute('PRAGMA table_info(users)')}


def test_cross_identifier_uniqueness(app):
    with app.app_context():
        db.session.add(User(username='other',email='EXISTING.EMPLOYEE',full_name='Other',department='X',employment_status='Active'))
        with pytest.raises(ValueError,match='Conflicting'):db.session.commit()
        db.session.rollback()


def test_change_password_rejects_wrong_current_and_mismatch(app,client):
    login(client,app)
    for current,new,confirm in [('wrong-current-value',secrets.token_urlsafe(24),secrets.token_urlsafe(24)),
                                (app.config['TEST_PASSWORD'],secrets.token_urlsafe(24),secrets.token_urlsafe(24))]:
        r=client.post('/change-password',data={'csrf_token':csrf(client,'/change-password'),
            'current_password':current,'new_password':new,'confirm_password':confirm})
        assert r.status_code==400
    with app.app_context():assert PasswordHasher().verify(User.query.one().password_hash,app.config['TEST_PASSWORD'])


def test_invalid_hash_fails_closed(app,client):
    modify(app,password_hash='not-a-valid-hash')
    assert login(client,app).status_code==401


def test_cli_permanent_password(app):
    password=secrets.token_urlsafe(24)
    r=app.test_cli_runner().invoke(args=['auth','set-password','--username','existing.employee','--permanent'],input=password+'\n'+password+'\n')
    assert r.exit_code==0
    with app.app_context():assert not User.query.one().must_change_password


def test_migration_rollback_on_error(tmp_path):
    path=tmp_path/'legacy.db';old_database(path)
    with sqlite3.connect(path) as c:
        c.execute("CREATE TRIGGER prevent_update BEFORE UPDATE ON users BEGIN SELECT RAISE(ABORT,'test failure'); END")
    with pytest.raises(sqlite3.Error):migrate_database(path)
    with sqlite3.connect(path) as c:
        assert 'password_hash' not in {r[1] for r in c.execute('PRAGMA table_info(users)')}
        assert c.execute('SELECT count(*) FROM users').fetchone()[0]==1
    assert list((tmp_path/'auth_backups').glob('*.bak'))


def test_read_only_role_cannot_submit_review(app,client):
    app.config['SOC_REVIEW_ROLES']=set()
    login(client,app)
    assert client.get('/dashboard').status_code==200
    token=csrf(client,'/change-password')
    assert client.post('/alerts/1/review',data={'csrf_token':token,'analyst_status':'Open'}).status_code==403


def test_forwarded_headers_ignored_by_default(app,client,caplog):
    token=csrf(client)
    client.post('/login',data={'csrf_token':token,'identifier':'existing.employee','password':app.config['TEST_PASSWORD']},
                headers={'X-Forwarded-For':'203.0.113.77','X-Forwarded-Proto':'https'})
    assert '"ip": "127.0.0.1"' in caplog.text
    assert '203.0.113.77' not in caplog.text


def test_trusted_proxy_is_explicit(tmp_path):
    app=create_app({'TESTING':True,'TRUSTED_PROXY_HOPS':1,'RATELIMIT_ENABLED':False,
                   'SQLALCHEMY_DATABASE_URI':'sqlite:///'+str(tmp_path/'proxy.db')})
    with app.test_client() as c:
        c.get('/login',headers={'X-Forwarded-For':'203.0.113.77','X-Forwarded-Proto':'https'})
        from flask import request
        assert request.remote_addr=='203.0.113.77' and request.is_secure
