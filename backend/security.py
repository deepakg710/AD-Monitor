from __future__ import annotations
import secrets
from datetime import timedelta
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, InvalidHashError
from fastapi import HTTPException, Request
from .db import now, dt, stamp, digest, uid, audit

HASHER=PasswordHasher(time_cost=3,memory_cost=32768,parallelism=1)
DUMMY=HASHER.hash(secrets.token_urlsafe(32))

DISALLOWED_PASSWORDS=frozenset({
    'admin12345',
    'admin123456',
    'admin12345678',
    'adminpassword123!',
    'password12345',
    'password123456',
    'changeme12345',
    'administrator',
    'welcome12345',
})

def validate_password_strength(username:str,password:str)->None:
    if not 12<=len(password)<=256:
        raise ValueError('Password must contain 12–256 characters')
    norm=password.strip().lower()
    if norm in DISALLOWED_PASSWORDS or norm==username.strip().lower():
        raise ValueError('Default, shared, or username-matching passwords are not permitted. Choose a unique 12+ character passphrase.')

def create_user(c,username,password,role='Admin',actor='local-cli'):
    if not 3<=len(username)<=64 or not username.replace('.','').replace('_','').replace('-','').isalnum(): raise ValueError('Username must be 3–64 letters, digits, dots, dashes or underscores')
    validate_password_strength(username,password)
    ident=uid(); c.execute('INSERT INTO users VALUES(?,?,?,?,1,?)',(ident,username,HASHER.hash(password),role,now()))
    audit(c,actor,'user_created',{'id':ident,'username':username,'role':role}); return ident

def current(request:Request):
    auth=request.headers.get('authorization','')
    bearer=auth[7:].strip() if auth.startswith('Bearer ') else ''
    token=request.cookies.get('admonitor_session','') or bearer
    with request.app.state.db.read() as c:
        user=c.execute('SELECT u.id,u.username,u.role,s.csrf FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>? AND u.enabled=1',(digest(token),now())).fetchone()
    if not user: raise HTTPException(401,'Please sign in')
    if request.method not in ('GET','HEAD','OPTIONS') and not bearer and not secrets.compare_digest(request.headers.get('x-csrf-token',''),user['csrf']): raise HTTPException(403,'Missing or invalid CSRF token')
    return dict(user)

def require(request,role):
    u=current(request)
    if {'Viewer':0,'Analyst':1,'Admin':2}[u['role']]<{'Viewer':0,'Analyst':1,'Admin':2}[role]: raise HTTPException(403,role+' permission required')
    return u

def login(db,username,password,ip):
    identity=digest(ip); error=None; result=None
    with db.tx() as c:
        attempt=c.execute('SELECT * FROM login_attempts WHERE identity=?',(identity,)).fetchone()
        if attempt and attempt['failures']>=8 and attempt['until_time']>now(): raise HTTPException(429,'Too many login attempts; wait 15 minutes')
        user=c.execute('SELECT * FROM users WHERE username=?',(username,)).fetchone()
        if password.strip().lower() in DISALLOWED_PASSWORDS:
            valid=False
            audit(c,'anonymous','disallowed_default_password_blocked',{'username':username,'source_hash':identity})
        else:
            try: valid=HASHER.verify(user['password_hash'] if user else DUMMY,password)
            except (VerificationError,InvalidHashError): valid=False
        if not user or not valid or not user['enabled']:
            failures=attempt['failures']+1 if attempt and attempt['until_time']>now() else 1
            c.execute('INSERT INTO login_attempts VALUES(?,?,?) ON CONFLICT(identity) DO UPDATE SET failures=excluded.failures,until_time=excluded.until_time',(identity,failures,stamp(dt(now())+timedelta(minutes=15))))
            audit(c,'anonymous','login_failed',{'source_hash':identity}); error=HTTPException(401,'Invalid username or password')
        else:
            c.execute('DELETE FROM login_attempts WHERE identity=?',(identity,))
            token=secrets.token_urlsafe(48); csrf=secrets.token_urlsafe(32)
            c.execute('INSERT INTO sessions VALUES(?,?,?,?)',(digest(token),user['id'],csrf,stamp(dt(now())+timedelta(hours=8))))
            audit(c,user['username'],'login',{})
            result={'token':token,'csrf':csrf,'user':{'id':user['id'],'username':user['username'],'role':user['role']}}
    if error: raise error
    return result
