from __future__ import annotations
import contextlib, hashlib, json, os, sqlite3, threading, uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path

UTC = timezone.utc
def now(): return datetime.now(UTC).isoformat(timespec='microseconds').replace('+00:00', 'Z')
def stamp(value):
    d = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
    if d.tzinfo is None: raise ValueError('Timestamp requires a timezone')
    return d.astimezone(UTC).isoformat(timespec='microseconds').replace('+00:00', 'Z')
def dt(value): return datetime.fromisoformat(value.replace('Z', '+00:00'))
def ago(seconds): return (datetime.now(UTC)-timedelta(seconds=seconds)).isoformat(timespec='microseconds').replace('+00:00','Z')
def uid(): return str(uuid.uuid4())
def digest(value): return hashlib.sha256(value.encode()).hexdigest()
def js(value): return json.dumps(value, ensure_ascii=False, separators=(',', ':'), allow_nan=False)
def obj(value): return json.loads(value) if value else None
def audit(c, actor, action, details): c.execute('INSERT INTO audit VALUES(?,?,?,?,?)', (uid(), now(), actor, action, js(details)))
def row(r): return dict(r) if r else None

class Database:
    def __init__(self, path):
        self.path = Path(path).resolve(); self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
    def connect(self):
        c = sqlite3.connect(self.path, timeout=15)
        c.row_factory = sqlite3.Row
        c.execute('PRAGMA foreign_keys=ON'); c.execute('PRAGMA busy_timeout=15000')
        return c
    @contextlib.contextmanager
    def tx(self):
        with self.lock:
            c = self.connect()
            try:
                c.execute('BEGIN IMMEDIATE'); yield c; c.commit()
            except BaseException: c.rollback(); raise
            finally: c.close()
    @contextlib.contextmanager
    def read(self):
        c = self.connect()
        try: yield c
        finally: c.close()
    def migrate(self):
        with self.lock:
            c = self.connect(); c.execute('PRAGMA journal_mode=WAL')
            c.execute('CREATE TABLE IF NOT EXISTS schema_version(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)')
            for f in sorted((Path(__file__).parent/'migrations').glob('*.sql')):
                if f.name.endswith('.down.sql'): continue
                v=int(f.name.split('_')[0])
                if not c.execute('SELECT 1 FROM schema_version WHERE version=?',(v,)).fetchone():
                    c.executescript('BEGIN IMMEDIATE;\n'+f.read_text(encoding='utf-8'))
                    c.execute('INSERT INTO schema_version VALUES(?,?)',(v,now())); c.commit()
            c.close()
    def rollback_migration(self, target_version=2):
        with self.lock:
            c = self.connect()
            try:
                if isinstance(target_version, str):
                    v_num = int(Path(target_version).name.split('_')[0])
                    target_version = v_num - 1
                rows = c.execute('SELECT version FROM schema_version WHERE version>? ORDER BY version DESC',(target_version,)).fetchall()
                for r in rows:
                    v = r['version']
                    downs = list((Path(__file__).parent/'migrations').glob(f'{v:03d}_*.down.sql'))
                    if not downs: raise ValueError(f'No down-migration found for version {v}')
                    c.executescript('BEGIN IMMEDIATE;\n'+downs[0].read_text(encoding='utf-8'))
                    c.execute('DELETE FROM schema_version WHERE version=?',(v,))
                    c.commit()
                return bool(rows)
            finally:
                c.close()
    def backup(self, destination):
        destination=Path(destination)
        if destination.exists(): raise ValueError('Backup destination must not exist')
        with self.lock, self.read() as source:
            target=sqlite3.connect(destination)
            try: source.backup(target)
            finally: target.close()

DEFAULT_SETTINGS = {
    'timezone':'Asia/Kolkata','event_retention_days':90,'health_retention_days':14,'alert_retention_days':365,
    'raw_retention_days':30,'process_sample_retention_days':7,'process_lifecycle_retention_days':30,'browser_retention_days':30,
    'max_pending_records':10000,'min_free_mb':256,
    'business_start':9,'business_end':18,'business_days':[0,1,2,3,4],
    'sensitive_paths':['C:\\ADMonitor-Demo\\Sensitive','C:\\ADMonitor-Demo\\HR','C:\\ADMonitor-Demo\\Finance'],
    'restricted_domains':[],
    'path_mappings':[{'source':'\\\\WIN-8IIRPFSV4GI.lab.local\\ADMonitor-Demo','target':'C:\\ADMonitor-Demo'},{'source':'\\\\WIN-8IIRPFSV4GI\\ADMonitor-Demo','target':'C:\\ADMonitor-Demo'}],
    'model_min_windows':48,'model_min_days':7,'model_user_min_windows':24,'model_contamination':0.05,
    'model_lateness_minutes':15
}
def settings(c):
    return {**DEFAULT_SETTINGS, **{r['key']:obj(r['value']) for r in c.execute('SELECT * FROM settings')}}

def presence(last, at=None):
    if not last: return 'Unknown'
    try: age=((at or datetime.now(UTC))-dt(last)).total_seconds()
    except (ValueError,TypeError): return 'Unknown'
    if age < 0: return 'Unknown'
    return 'Online' if age < 60 else 'Stale' if age <= 180 else 'Offline'
