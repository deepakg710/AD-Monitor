"""CPU-only, explicit training, temporal holdout, persisted preprocessing and provenance."""
from __future__ import annotations
import hashlib, math
from datetime import timedelta
from pathlib import Path
import joblib
import numpy as np
from .model import LightweightIsolationForest

class PureImputerScaler:
    def __init__(self):
        self.mean = None
        self.std = None
    def fit(self, X):
        clean = np.nan_to_num(X, nan=0.0)
        self.mean = np.mean(clean, axis=0)
        self.std = np.std(clean, axis=0)
        self.std[self.std == 0] = 1.0
        return self
    def transform(self, X):
        clean = np.nan_to_num(X, nan=0.0)
        return (clean - self.mean) / self.std
    def fit_transform(self, X):
        return self.fit(X).transform(X)

class PureIsolationForestPipeline:
    def __init__(self, contamination=0.05, random_state=42):
        self.scaler = PureImputerScaler()
        self.forest = LightweightIsolationForest(n_estimators=100, max_samples=256, contamination=contamination, random_state=random_state)
    def fit(self, X):
        scaled = self.scaler.fit_transform(X)
        self.forest.fit(scaled)
        return self
    def decision_function(self, X):
        scaled = self.scaler.transform(X)
        scores = self.forest.score_samples(scaled)
        return self.forest.threshold - scores

from .db import now, dt, stamp, js, obj, uid, digest, settings, audit
from .normalize import scoped
from .rules import after_hours

SCHEMA=1
NAMES=['event_count','file_read_count','distinct_sensitive_paths','denied_fraction','after_hours_fraction','device_novelty_fraction','unknown_device_fraction']
UNITS=['events/hour','reads/hour','paths/hour','fraction','fraction','fraction','fraction']

def extract(c,provenance='operational'):
    policy=settings(c); end=dt(now())-timedelta(minutes=policy['model_lateness_minutes'])
    end=end.replace(minute=0,second=0,microsecond=0)
    rows=c.execute('SELECT * FROM events WHERE user_sid IS NOT NULL AND time<? ORDER BY time,id LIMIT 100001',(stamp(end),)).fetchall()
    if len(rows)>100000: raise ValueError('Feature extraction exceeds 100000 events; reduce retention or export an offline study')
    blocked={r['event_id'] for r in c.execute("SELECT ae.event_id FROM alert_evidence ae JOIN alerts a ON a.id=ae.alert_id WHERE a.disposition='suspicious'")}
    windows={}; history={}
    for r in rows:
        f=obj(r['fields']); sid=r['user_sid']; hour=dt(r['time']).replace(minute=0,second=0,microsecond=0)
        key=(sid,stamp(hour)); entry=windows.setdefault(key,{'events':[],'novel':0,'known':0,'excluded':False})
        entry['events'].append(r)
        if r['id'] in blocked or f.get('controlled_test'): entry['excluded']=True
        device=r['access_device_id']
        if device:
            entry['known']+=1
            if device not in history.setdefault(sid,set()): entry['novel']+=1
        # Historical novelty refers only to PREVIOUS hourly windows, never later evidence.
    history={}; result=[]
    for (sid,start),entry in sorted(windows.items(),key=lambda x:x[0][1]):
        ev=entry['events']; n=len(ev); devices={r['access_device_id'] for r in ev if r['access_device_id']}
        known=[r for r in ev if r['access_device_id']]; previous=history.setdefault(sid,set())
        novelty=sum(r['access_device_id'] not in previous for r in known)/len(known) if known else None
        values=[n,sum(r['category']=='file_read' for r in ev),len({r['canonical_path'] for r in ev if r['category']=='file_read' and scoped(r['canonical_path'],policy['sensitive_paths'])}),
            sum(r['result']=='denied' for r in ev)/n,sum(after_hours(r['time'],policy) for r in ev)/n,novelty,1-len(known)/n]
        history[sid].update(devices)
        feature={'id':digest(js([sid,start,SCHEMA])),'user_sid':sid,'start_time':start,'end_time':stamp(dt(start)+timedelta(hours=1)),
            'values':values,'evidence':[r['id'] for r in ev],'excluded':entry['excluded'],'provenance':provenance}
        c.execute('INSERT INTO features VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(user_sid,start_time,schema_version) DO UPDATE SET values_json=excluded.values_json,evidence_ids=excluded.evidence_ids,provenance=excluded.provenance',
            (feature['id'],sid,start,feature['end_time'],SCHEMA,js({'values':values,'excluded':entry['excluded']}),js(feature['evidence']),provenance))
        result.append(feature)
    return result

def fit_bundle(features,policy,provenance):
    clean=sorted([f for f in features if not f['excluded']],key=lambda f:f['start_time'])
    # Split at a time boundary so all users from one hour stay on the same side.
    hours=sorted({f['start_time'] for f in clean})
    if len(hours)<2: raise ValueError('Collecting baseline: insufficient independent hourly windows')
    boundary=hours[max(1,int(len(hours)*0.8))]
    train=[f for f in clean if f['start_time']<boundary]; test=[f for f in clean if f['start_time']>=boundary]
    days=(dt(train[-1]['end_time'])-dt(train[0]['start_time'])).total_seconds()/86400 if train else 0
    if len(train)<policy['model_min_windows'] or days<policy['model_min_days']:
        raise ValueError(f"Collecting baseline: training split has {len(train)} windows over {days:.1f} days; requires {policy['model_min_windows']} windows and {policy['model_min_days']} days")
    matrix=lambda rows: np.asarray([[float(v) if v is not None else np.nan for v in f['values']] for f in rows],dtype=float)
    def fit(rows):
        x=matrix(rows)
        model=PureIsolationForestPipeline(contamination=policy['model_contamination'],random_state=42)
        model.fit(x)
        return {'pipeline':model,'mean':np.nan_to_num(np.nanmean(x,axis=0)).tolist(),'std':np.nan_to_num(np.nanstd(x,axis=0)).tolist(),'samples':len(rows)}
    if np.nanmax(np.nanstd(matrix(train),axis=0))==0: raise ValueError('Collecting baseline: all measured features are constant')
    bundle={'global':fit(train),'users':{},'schema':SCHEMA,'names':NAMES,'units':UNITS,'train_end':max(f['end_time'] for f in train)}
    for sid in {f['user_sid'] for f in train}:
        user=[f for f in train if f['user_sid']==sid]
        if len(user)>=policy['model_user_min_windows'] and (dt(user[-1]['end_time'])-dt(user[0]['start_time'])).total_seconds()/86400>=policy['model_min_days']:
            bundle['users'][sid]=fit(user)
    scores=bundle['global']['pipeline'].decision_function(matrix(test)) if test else np.array([])
    metadata={'schema_version':SCHEMA,'features':dict(zip(NAMES,UNITS)),'training_start':train[0]['start_time'],'training_end':bundle['train_end'],
        'samples':len(train),'holdout_samples':len(test),'holdout_start':boundary,'holdout_findings':int(np.sum(scores<0)),
        'threshold':0,'score_definition':'IsolationForest decision_function; below zero indicates an outlier, never maliciousness probability',
        'evaluation':'Temporal unlabeled holdout. Precision/recall unavailable without independent labels.',
        'provenance':provenance,'per_user_baselines':len(bundle['users']),'fallback':'Explicit global population baseline for sparse users',
        'policy':policy,'excluded_windows':len(features)-len(clean),'training_feature_ids':[f['id'] for f in train]}
    return bundle,metadata

def train(db,actor,provenance='operational'):
    with db.tx() as c: features=extract(c,provenance); policy=settings(c)
    bundle,metadata=fit_bundle(features,policy,provenance)
    mid=uid(); folder=db.path.parent/'models'; folder.mkdir(exist_ok=True); path=folder/(mid+'.joblib')
    joblib.dump(bundle,path); sha=hashlib.sha256(path.read_bytes()).hexdigest()
    with db.tx() as c:
        c.execute('UPDATE models SET active=0')
        c.execute('INSERT INTO models VALUES(?,?,1,?,?,?)',(mid,now(),js(metadata),str(path),sha))
        audit(c,actor,'model_train',{'model_id':mid,'metadata':metadata})
    return {'id':mid,'metadata':metadata}

def score(db,actor='worker'):
    with db.tx() as c:
        model=c.execute('SELECT * FROM models WHERE active=1').fetchone()
        if not model: return {'state':'Collecting baseline','scored':0}
        features=extract(c); model=dict(model)
    path=Path(model['path']).resolve(); folder=(db.path.parent/'models').resolve()
    if path.parent!=folder or hashlib.sha256(path.read_bytes()).hexdigest()!=model['sha256']: raise ValueError('Model artifact path or integrity check failed')
    bundle=joblib.load(path)  # only self-created, hash-checked local artifact; never an uploaded pickle
    count=0; findings=0
    with db.tx() as c:
        for f in features:
            if f['start_time']<bundle['train_end'] or f['excluded']: continue
            if c.execute('SELECT 1 FROM model_scores WHERE model_id=? AND feature_id=?',(model['id'],f['id'])).fetchone(): continue
            base=bundle['users'].get(f['user_sid'],bundle['global']); kind='per-user' if f['user_sid'] in bundle['users'] else 'global fallback (sparse user)'
            x=np.array([[float(v) if v is not None else np.nan for v in f['values']]])
            value=float(base['pipeline'].decision_function(x)[0]); deviations=[]
            for i,v in enumerate(f['values']):
                if v is not None:
                    deviations.append({'feature':NAMES[i],'observed':v,'baseline_mean':base['mean'][i],'baseline_std':base['std'][i],
                        'standardized_deviation':(v-base['mean'][i])/base['std'][i] if base['std'][i]>0 else None})
            deviations.sort(key=lambda d:abs(d['standardized_deviation'] or 0),reverse=True)
            explanation={'score':value,'threshold':0,'baseline':kind,'baseline_samples':base['samples'],'deviations':deviations,
                'note':'Descriptive deviations are not causal feature contributions. Score is not a probability.','model_id':model['id'],'window_start':f['start_time'],'window_end':f['end_time']}
            c.execute('INSERT INTO model_scores VALUES(?,?,?,?,?)',(model['id'],f['id'],value,kind,js(explanation))); count+=1
            if value<0:
                aid=uid(); fingerprint=digest(js([model['id'],f['id']]))
                c.execute('INSERT OR IGNORE INTO alerts(id,fingerprint,kind,title,severity,user_sid,first_time,last_time,created_at,explanation,config_snapshot) VALUES(?,?,?,?,?,?,?,?,?,?,?)',
                    (aid,fingerprint,'model','Unusual hourly behavior','Medium',f['user_sid'],f['start_time'],f['end_time'],now(),js(explanation),model['metadata']))
                for eid in f['evidence']: c.execute('INSERT OR IGNORE INTO alert_evidence VALUES(?,?)',(aid,eid))
                findings+=1
        audit(c,actor,'model_score',{'model_id':model['id'],'scored':count,'findings':findings})
    return {'scored':count,'findings':findings}

def run_job(db):
    with db.tx() as c:
        job=c.execute("SELECT * FROM jobs WHERE status='Queued' ORDER BY created_at LIMIT 1").fetchone()
        if not job: return False
        c.execute("UPDATE jobs SET status='Running' WHERE id=?",(job['id'],))
    try:
        result=train(db,job['actor']) if job['kind']=='train' else score(db,job['actor'])
        with db.tx() as c: c.execute("UPDATE jobs SET status='Completed',completed_at=?,result=? WHERE id=?",(now(),js(result),job['id']))
    except Exception as exc:
        with db.tx() as c: c.execute("UPDATE jobs SET status='Failed',completed_at=?,error=? WHERE id=?",(now(),str(exc)[:500],job['id']))
    return True
