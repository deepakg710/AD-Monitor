"""Bounded durable spool and TLS transport, shared by Windows components."""
import ctypes, hashlib, json, logging, os, sqlite3, ssl, urllib.request, urllib.parse
from pathlib import Path
from datetime import datetime,timezone

def timestamp(): return datetime.now(timezone.utc).isoformat(timespec='microseconds').replace('+00:00','Z')
def encode(value): return json.dumps(value,separators=(',',':'),ensure_ascii=False,allow_nan=False)
class QueueFull(Exception): pass
class Spool:
    def __init__(self,path,max_bytes=50*1024*1024):
        self.path=Path(path); self.path.parent.mkdir(parents=True,exist_ok=True); self.max_bytes=max_bytes
        with self.connect() as c:
            c.execute('PRAGMA journal_mode=WAL'); c.execute('CREATE TABLE IF NOT EXISTS queue(id TEXT PRIMARY KEY,payload TEXT NOT NULL,created TEXT NOT NULL)');c.execute('CREATE TABLE IF NOT EXISTS state(key TEXT PRIMARY KEY,value TEXT NOT NULL)')
    def connect(self): return sqlite3.connect(self.path,timeout=15)
    def state(self,key,default=None):
        with self.connect() as c: r=c.execute('SELECT value FROM state WHERE key=?',(key,)).fetchone()
        return json.loads(r[0]) if r else default
    def put(self,records,states=None):
        prepared=[(r['id'],encode(r),timestamp()) for r in records]
        with self.connect() as c:
            c.execute('BEGIN IMMEDIATE'); size=c.execute('SELECT COALESCE(SUM(length(CAST(payload AS BLOB))),0) FROM queue').fetchone()[0]
            if size+sum(len(r[1].encode()) for r in prepared)>self.max_bytes: raise QueueFull('Retry queue capacity reached; collection paused, no unacknowledged records removed')
            c.executemany('INSERT OR IGNORE INTO queue VALUES(?,?,?)',prepared)
            for k,v in (states or {}).items(): c.execute('INSERT INTO state VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',(k,encode(v)))
    def batch(self):
        result=[]; size=0
        with self.connect() as c: rows=c.execute('SELECT id,payload FROM queue ORDER BY created,id LIMIT 50').fetchall()
        for ident,payload in rows:
            size+=len(payload.encode())
            if size>1400000: break
            result.append(json.loads(payload))
        return result
    def acknowledge(self,ids):
        with self.connect() as c: c.executemany('DELETE FROM queue WHERE id=?',[(s,) for s in ids])
        with self.connect() as c: c.execute('PRAGMA wal_checkpoint(TRUNCATE)')
    def stats(self):
        with self.connect() as c: r=c.execute('SELECT COUNT(*),COALESCE(SUM(length(CAST(payload AS BLOB))),0),MIN(created) FROM queue').fetchone()
        return {'queue_depth':r[0],'queue_bytes':r[1],'oldest_queued':r[2]}

class Blob(ctypes.Structure): _fields_=[('length',ctypes.c_uint32),('data',ctypes.POINTER(ctypes.c_ubyte))]
def dpapi(value,protect):
    if os.name!='nt': raise RuntimeError('Windows DPAPI is required')
    buf=ctypes.create_string_buffer(value); source=Blob(len(value),ctypes.cast(buf,ctypes.POINTER(ctypes.c_ubyte))); out=Blob()
    crypt=ctypes.WinDLL('crypt32',use_last_error=True); kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    fn=crypt.CryptProtectData if protect else crypt.CryptUnprotectData
    fn.argtypes=[ctypes.POINTER(Blob),ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_uint32,ctypes.POINTER(Blob)]; fn.restype=ctypes.c_int
    kernel.LocalFree.argtypes=[ctypes.c_void_p]; kernel.LocalFree.restype=ctypes.c_void_p
    # LOCAL_MACHINE scope; file ACL must restrict access to the scheduled-task account, SYSTEM and administrators.
    if not fn(ctypes.byref(source),None,None,None,None,4 if protect else 0,ctypes.byref(out)): raise ctypes.WinError(ctypes.get_last_error())
    try: return ctypes.string_at(out.data,out.length)
    finally: kernel.LocalFree(out.data)
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs): raise ValueError('Collector endpoint redirects are not allowed')
class Transport:
    def __init__(self,config):
        self.base=config['backend_url'].rstrip('/'); parsed=urllib.parse.urlparse(self.base)
        if parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ('','/'): raise ValueError('Backend URL must be an origin without credentials, query or path')
        if parsed.scheme!='https' and not (config.get('loopback_development') and parsed.scheme=='http' and parsed.hostname in ('127.0.0.1','localhost')): raise ValueError('Cross-machine collection requires HTTPS with certificate validation')
        token=dpapi(Path(config['token_file']).read_bytes(),False).decode()
        self.headers={'Authorization':'Bearer '+token,'Content-Type':'application/json'}
        ctx=ssl.create_default_context(cafile=config.get('ca_file') or None)
        self.opener=urllib.request.build_opener(NoRedirect(),urllib.request.HTTPSHandler(context=ctx),urllib.request.ProxyHandler({}))
    def post(self,path,body):
        req=urllib.request.Request(self.base+path,encode(body).encode(),headers=self.headers,method='POST')
        with self.opener.open(req,timeout=15) as response: return json.loads(response.read(2*1024*1024))
    def flush(self,spool,diagnostics):
        import uuid
        records=spool.batch()
        if not records: return 0
        result=self.post('/api/ingest',{'schema_version':2,'transport_id':str(uuid.uuid4()),'records':records,'diagnostics':{**spool.stats(),**diagnostics}})
        expected={r['id'] for r in records}; ack=set(result.get('acknowledged') or result.get('accepted') or [])
        if not ack.issubset(expected) or not ack: raise ValueError('Invalid acknowledgment; retry queue retained')
        spool.acknowledge(ack); return len(ack)
