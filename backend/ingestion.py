from __future__ import annotations
import json, logging, os, shutil, threading, time
from datetime import timedelta
from pathlib import Path
from .db import now, dt, stamp, js, obj, uid, digest, row, settings, audit
from .normalize import parse_xml, canonical
from .rules import evaluate_with_late
from .telemetry import (
    ingest_process_snapshot,
    ingest_process_lifecycle,
    record_lifecycle_from_event,
    ingest_browser_enrollment,
    ingest_browser_status,
    ingest_browser_navigation,
    ingest_browser_download,
)

LOG=logging.getLogger('admonitor')

def insert(c,table,values,ignore=False):
    cols=','.join(values); marks=','.join('?' for _ in values)
    return c.execute(f"INSERT {'OR IGNORE ' if ignore else ''}INTO {table}({cols}) VALUES({marks})",tuple(values.values()))

def find_device(c,host):
    if not host: return None
    # Prefer exact FQDN; short-name matching is permitted only when unambiguous.
    host=host.casefold().rstrip('.')
    rows=c.execute('SELECT * FROM devices').fetchall()
    exact=[r for r in rows if r['hostname'].casefold().rstrip('.')==host]
    matches=exact or [r for r in rows if r['hostname'].split('.')[0].casefold()==host.split('.')[0]]
    return matches[0]['id'] if len(matches)==1 else None

def attribute(c,e):
    e['device_id']=find_device(c,e['source_computer'])
    f=obj(e['fields'])
    if not e['user_sid'] and e['account']:
        short=e['account'].split('\\')[-1].split('@')[0].lower()
        users=c.execute('SELECT sid,account FROM employees WHERE lower(account)=lower(?) OR lower(account) LIKE ?',(e['account'],'%\\'+short)).fetchall()
        if len(users)==1:
            e['user_sid']=users[0]['sid']
            e['account']=users[0]['account']
    elif e['user_sid'] and (not e['account'] or '\\' not in e['account']):
        u=c.execute('SELECT account FROM employees WHERE sid=?',(e['user_sid'],)).fetchone()
        if u and u['account']: e['account']=u['account']
    if e['device_id']: c.execute('UPDATE devices SET last_event=MAX(COALESCE(last_event,?),?) WHERE id=?',(e['time'],e['time'],e['device_id']))
    # Endpoint-origin process/file evidence is associated with its producing device. A DC remains the producer.
    if e['category'] in ('process_start','process_end','script_block','download','file_copy','archive_create','file_change','file_rename'):
        e['access_device_id']=e['device_id']; e['attribution']='Strong: endpoint producing device' if e['device_id'] else 'Unknown'
    elif e['category']=='sign_in':
        wk=find_device(c,f.get('WorkstationName') or f.get('Workstation'))
        if wk:
            e['access_device_id']=wk; e['attribution']='Strong: workstation field from authentication record'
        elif e['device_id'] and not str(e['source_computer'] or '').lower().startswith('win-8iirpfsv4gi'):
            e['access_device_id']=e['device_id']; e['attribution']='Strong: local interactive authentication record'
    if e['logon_id'] and e['category'] not in ('sign_in','sign_out'):
        logon=c.execute("SELECT * FROM events WHERE source_computer=? AND logon_id=? AND category='sign_in' AND result='success' AND time<=? AND time>=? ORDER BY time DESC LIMIT 1",
            (e['source_computer'],e['logon_id'],e['time'],stamp(dt(e['time'])-timedelta(hours=12)))).fetchone()
        if logon and (not e['user_sid'] or logon['user_sid']==e['user_sid']):
            ended=c.execute("SELECT 1 FROM events WHERE source_computer=? AND logon_id=? AND category='sign_out' AND time>? AND time<=? LIMIT 1",(e['source_computer'],e['logon_id'],logon['time'],e['time'])).fetchone()
            if not ended:
                lf=obj(logon['fields']); target=find_device(c,lf.get('WorkstationName'))
                e['source_address']=e['source_address'] or logon['source_address']
                if target:
                    e['access_device_id']=target; e['attribution']='Strong: same-server logon ID, SID, time and workstation; workstation field is not cryptographic proof'
                elif lf.get('LogonType') in ('2','10','11') and e['device_id']:
                    e['access_device_id']=e['device_id']; e['attribution']='Strong: same-server interactive logon session'
    confidence='Strong'
    if not e['access_device_id'] and e['source_address'] and e['source_address'] not in ('-','::1','127.0.0.1'):
        ip=e['source_address'].replace('::ffff:','')
        hits=[r['id'] for r in c.execute('SELECT id,ips FROM devices WHERE ips IS NOT NULL') if ip in (obj(r['ips']) or [])]
        if len(hits)==1:
            e['access_device_id']=hits[0]; confidence='Medium'
            e['attribution']='Medium: source IP uniquely matches device IP from inventory/heartbeat; IP is not proof of device (DHCP/NAT/reuse)'
    if e['access_device_id'] and e['user_sid']:
        c.execute('INSERT INTO associations VALUES(?,?,?,?,?,?,0) ON CONFLICT(employee_sid,device_id) DO UPDATE SET last_seen=MAX(last_seen,excluded.last_seen),confidence=excluded.confidence,reason=excluded.reason',
            (e['user_sid'],e['access_device_id'],confidence,e['attribution'],e['time'],e['time']))

def observation(payload,collector,received,policy):
    data=payload['data']; kind=data['category']; fields=dict(data.get('fields') or data)
    if kind not in ('download','file_copy','archive_create','file_change','file_rename','script_block','network_connection','privilege_change','sign_in'): raise ValueError('Unsupported observation category')
    if kind in ('download','file_copy'):
        raw_bytes=fields.get('bytes')
        if not isinstance(raw_bytes,int) or isinstance(raw_bytes,bool) or raw_bytes<0:
            raise ValueError('Measured non-negative integer bytes required for download/file_copy observation; fabricated byte defaults are prohibited')
    when=stamp(data.get('time') or payload.get('time') or received); host=collector['expected_host']
    if data.get('hostname') and host and data['hostname'].split('.')[0].casefold()!=host.split('.')[0].casefold(): raise ValueError('Observation host does not match enrollment')
    path=fields.get('destination_path') or fields.get('path') or fields.get('source_path')
    cmd=fields.get('command_line')
    res='denied' if data.get('result')=='denied' or fields.get('result')=='denied' else 'observed'
    acct=data.get('account') if data.get('account') else None
    sid=data.get('user_sid') if data.get('user_sid') else None
    attr='Strong: enrolled endpoint; actor supplied by local operation' if sid else ('Medium: enrolled endpoint account' if acct else 'Device known; employee unknown')
    ident_key=digest(js([collector['id'],kind,str(path).casefold(),fields.get('bytes'),when[:15]])) if kind=='file_copy' and path else digest(js([collector['id'],payload['id']]))
    return dict(id=uid(),identity=ident_key,time=when,received_at=received,event_id=fields.get('event_id'),
        provider='ADMonitor.InstrumentedOperation' if kind in ('download','file_copy','archive_create') else 'ADMonitor.MetadataSnapshot',
        channel='ADMonitor',source_computer=host or data.get('hostname') or 'unknown-host',collector_id=collector['id'],source_record=payload['id'],user_sid=sid,
        account=acct,logon_id=None,device_id=collector['device_id'],access_device_id=collector['device_id'],
        attribution=attr,
        category=kind,result=res,object_path=path,canonical_path=canonical(path,policy['path_mappings']) if path else None,source_address=fields.get('IpAddress'),
        process_id=data.get('process_id'),process_guid=None,parent_id=None,process_path=fields.get('process_name'),command_line=cmd,
        fields=js(fields),raw=js(payload),evidence_type='instrumented_operation' if kind in ('download','file_copy','archive_create') else 'metadata_snapshot',late_seconds=(dt(received)-dt(when)).total_seconds())

def heartbeat(c,payload,collector,received):
    d=payload['data']; did=collector['device_id']
    if collector.get('expected_host') and d['hostname'].split('.')[0].casefold()!=collector['expected_host'].split('.')[0].casefold(): raise ValueError('Heartbeat hostname does not match enrollment')
    when=stamp(d['time']); hid=digest(collector['id']+payload['id']); errors=d.get('errors',[])
    if c.execute('SELECT 1 FROM heartbeats WHERE id=?',(hid,)).fetchone(): return
    c.execute('UPDATE devices SET os=?,ips=?,agent_version=?,last_heartbeat=?,errors=? WHERE id=?',
        (d.get('os'),js(d.get('ips',[])),d.get('agent_version'),received,js(errors),did))
    sessions=d.get('sessions',[])
    if isinstance(sessions,dict): sessions=[sessions] if (sessions.get('id') or sessions.get('account')) else []
    elif isinstance(sessions,list): sessions=[s for s in sessions if isinstance(s,dict) and (s.get('id') or s.get('account'))]
    else: sessions=[]
    insert(c,'heartbeats',dict(id=hid,device_id=did,sampled_at=when,received_at=received,sessions=js(sessions),errors=js(errors)))
    h=d.get('health',{})
    for field in ('cpu','ram_percent'):
        if h.get(field) is not None and not 0<=float(h[field])<=100: raise ValueError('Invalid health percentage')
    disks=h.get('disks',[])
    if isinstance(disks,dict): disks=[disks] if disks.get('device_id') else []
    elif not isinstance(disks,list): disks=[]
    insert(c,'health',dict(id=hid,device_id=did,sampled_at=when,received_at=received,cpu=h.get('cpu'),ram_percent=h.get('ram_percent'),
        ram_used=h.get('ram_used'),ram_available=h.get('ram_available'),ram_total=h.get('ram_total'),disks=js(disks)))
    for s in sessions[:100]:
        insert(c,'endpoint_sessions',dict(id=digest(hid+str(s.get('id'))),device_id=did,session_key=str(s.get('id')),account=s.get('account'),state=s.get('state'),observed_at=when))
    active_acct=sessions[0].get('account') if sessions else None
    usb_events=d.get('usb_events',[])
    if isinstance(usb_events,dict): usb_events=[usb_events] if usb_events.get('action') else []
    elif isinstance(usb_events,list): usb_events=[u for u in usb_events if isinstance(u,dict) and u.get('action')]
    else: usb_events=[]
    for u in usb_events[:100]:
        if u['action'] not in ('connected','disconnected','present_at_start'): raise ValueError('Invalid USB action')
        insert(c,'usb',dict(id=digest(collector['id']+str(u.get('id') or u.get('identifier'))+str(u.get('time'))),device_id=did,time=stamp(u['time']),received_at=received,action=u['action'],identifier=u['identifier'],account=u.get('account') or active_acct,metadata=js(u.get('metadata',{})),evidence_type='device_presence_only'),True)

def directory(c,payload,collector,received):
    d=payload['data']
    if not d.get('complete'): raise ValueError('Directory snapshot must be complete; failed sync must not erase inventory')
    for user in d['employees']:
        c.execute('INSERT INTO employees VALUES(?,?,?,?,?,?) ON CONFLICT(sid) DO UPDATE SET account=excluded.account,name=excluded.name,department=excluded.department,enabled=excluded.enabled,synced_at=excluded.synced_at',
            (user['sid'],user['account'],user.get('name'),user.get('department'),int(user.get('enabled',True)),received))
    for g in d['groups']: c.execute('INSERT INTO directory_groups VALUES(?,?,?) ON CONFLICT(sid) DO UPDATE SET name=excluded.name,synced_at=excluded.synced_at',(g['sid'],g['name'],received))
    for user in d['employees']:
        c.execute('DELETE FROM memberships WHERE employee_sid=?',(user['sid'],))
        for sid in user.get('group_sids',[]):
            if c.execute('SELECT 1 FROM directory_groups WHERE sid=?',(sid,)).fetchone(): c.execute('INSERT OR IGNORE INTO memberships VALUES(?,?)',(user['sid'],sid))
    for dev in d['computers']:
        existing=find_device(c,dev['hostname']); ips=[str(i) for i in (dev.get('ips') or []) if i][:10]
        if existing:
            c.execute('UPDATE devices SET sid=?,os=COALESCE(?,os),inventory_at=? WHERE id=?',(dev.get('sid'),dev.get('os'),received,existing))
            # Directory (DNS) IPs only fill the gap; endpoint heartbeat IPs are authoritative once received.
            if ips: c.execute("UPDATE devices SET ips=? WHERE id=? AND last_heartbeat IS NULL",(js(ips),existing))
        else: insert(c,'devices',dict(id=uid(),hostname=dev['hostname'],sid=dev.get('sid'),os=dev.get('os'),inventory_at=received,**({'ips':js(ips)} if ips else {})))
    audit(c,collector['id'],'directory_sync',{'employees':len(d['employees']),'computers':len(d['computers']),'source':'Authenticated DC bridge; integrated AD cmdlets'})

ALLOWED_KINDS_BY_COLLECTOR = {
    'wef': {'windows'},
    'bridge': {'windows'},
    'dc': {'directory', 'windows'},
    'directory': {'directory', 'windows'},
    'endpoint': {
        'heartbeat', 'observation', 'windows',
        'process_snapshot', 'process_lifecycle',
        'browser_enrollment', 'browser_status', 'browser_navigation', 'browser_download'
    },
    'browser': {
        'browser_enrollment', 'browser_status', 'browser_navigation', 'browser_download'
    }
}

def process_one(db):
    with db.tx() as c:
        record=c.execute(
            "SELECT * FROM inbox WHERE processed=0 "
            "ORDER BY CASE WHEN payload LIKE '%\"kind\":\"windows\"%' THEN 1 ELSE 0 END ASC, id ASC LIMIT 1"
        ).fetchone()
        if not record: return False
        collector_row=c.execute('SELECT * FROM collectors WHERE id=?',(record['collector_id'],)).fetchone()
        if not collector_row:
            c.execute("UPDATE inbox SET processed=-1,error='Collector not found' WHERE id=?",(record['id'],))
            return True
        collector=dict(collector_row)
        payload=obj(record['payload']); received=record['received_at']
        c.execute('SAVEPOINT normalize_record')
        try:
            kind=payload['kind']
            allowed=ALLOWED_KINDS_BY_COLLECTOR.get(collector['kind'],set())
            if allowed and kind not in allowed:
                raise ValueError(f"Collector kind '{collector['kind']}' is not authorized to submit record kind '{kind}'")
            policy=settings(c)
            if kind in ('windows','observation'):
                event=parse_xml(payload['xml'],collector['id'],received,policy['path_mappings']) if kind=='windows' else observation(payload,collector,received,policy)
                if dt(event['time'])>dt(received)+timedelta(minutes=5): raise ValueError('Source clock more than five minutes ahead; correct time and explicitly retry rejected record')
                attribute(c,event)
                acct_s=str(event.get('account') or '').strip()
                is_bg_noise=(
                    event.get('category') in ('sign_out','other')
                    or acct_s.endswith('$')
                    or event.get('user_sid') in ('S-1-5-18','S-1-5-19','S-1-5-20')
                    or (event.get('category')=='sign_in' and event.get('result')=='success' and (not acct_s or acct_s=='-' or 'administrator' in acct_s.casefold() or 'anonymous' in acct_s.casefold()))
                )
                cutoff_ts=getattr(db,'reset_cutoff',None)
                if cutoff_ts and dt(event['time'])<dt(cutoff_ts):
                    is_bg_noise=True
                made=0 if is_bg_noise else insert(c,'events',event,True).rowcount
                if made:
                    if event.get('category') in ('process_start','process_end') or event.get('event_id') in (4688,4689,1,5):
                        record_lifecycle_from_event(c,event,policy)
                    if event.get('category')=='file_copy':
                        fobj=obj(event.get('fields'))
                        dest=str(event.get('object_path') or fobj.get('destination_path') or '')
                        if fobj.get('destination_removable') or (len(dest)>=2 and dest[1]==':' and not dest.upper().startswith('C:')):
                            drv=dest[:2].upper() if len(dest)>=2 and dest[1]==':' else 'E:'
                            did=event.get('device_id') or collector['device_id']
                            if did:
                                insert(c,'usb',dict(id=digest(f"{did}_usbcopy_{drv}_{event['time'][:13]}"),device_id=did,time=event['time'],received_at=received,action='connected',identifier=f"USB Removable Drive ({drv})",account=event.get('account'),metadata=js({'model':f"Removable Storage Volume ({drv})",'last_transferred_file':dest,'bytes':fobj.get('bytes')}),evidence_type='device_presence_only'),True)
                    evaluate_with_late(c,event)
                    c.execute('UPDATE events SET rules_done=1 WHERE id=?',(event['id'],))
                c.execute('UPDATE collectors SET last_event=MAX(COALESCE(last_event,?),?) WHERE id=?',(event['time'],event['time'],collector['id']))
                col_dev=collector.get('device_id') or find_device(c,collector.get('expected_host'))
                if col_dev:
                    c.execute('UPDATE devices SET last_heartbeat=MAX(COALESCE(last_heartbeat,?),?) WHERE id=?',(received,received,col_dev))
            elif kind=='heartbeat': heartbeat(c,payload,collector,received)
            elif kind=='directory': directory(c,payload,collector,received)
            elif kind=='process_snapshot':
                ingest_process_snapshot(c,payload,collector,received,policy)
                c.execute('UPDATE collectors SET last_event=MAX(COALESCE(last_event,?),?) WHERE id=?',(received,received,collector['id']))
            elif kind=='process_lifecycle':
                ingest_process_lifecycle(c,payload,collector,received,policy)
                c.execute('UPDATE collectors SET last_event=MAX(COALESCE(last_event,?),?) WHERE id=?',(received,received,collector['id']))
            elif kind=='browser_enrollment':
                ingest_browser_enrollment(c,payload,collector,received)
                c.execute('UPDATE collectors SET last_event=MAX(COALESCE(last_event,?),?) WHERE id=?',(received,received,collector['id']))
            elif kind=='browser_status':
                ingest_browser_status(c,payload,collector,received)
                c.execute('UPDATE collectors SET last_event=MAX(COALESCE(last_event,?),?) WHERE id=?',(received,received,collector['id']))
            elif kind=='browser_navigation':
                ingest_browser_navigation(c,payload,collector,received,policy)
                c.execute('UPDATE collectors SET last_event=MAX(COALESCE(last_event,?),?) WHERE id=?',(received,received,collector['id']))
            elif kind=='browser_download':
                ingest_browser_download(c,payload,collector,received,policy)
                c.execute('UPDATE collectors SET last_event=MAX(COALESCE(last_event,?),?) WHERE id=?',(received,received,collector['id']))
            else: raise ValueError('Unknown record kind')
            c.execute('RELEASE normalize_record')
            c.execute('UPDATE inbox SET processed=1,payload=? WHERE id=?',(js({'kind':payload['kind'],'id':payload['id']}),record['id']))
        except Exception as exc:
            c.execute('ROLLBACK TO normalize_record'); c.execute('RELEASE normalize_record')
            message=str(exc)[:400]
            c.execute('UPDATE inbox SET processed=-1,error=? WHERE id=?',(message,record['id']))
            c.execute('UPDATE collectors SET parse_failures=parse_failures+1 WHERE id=?',(collector['id'],))
            LOG.warning('Record %s quarantined: %s',record['id'],type(exc).__name__)
    return True

def retention(db):
    with db.tx() as c:
        s=settings(c)
        cutoff=lambda key: stamp(dt(now())-timedelta(days=int(s.get(key,30))))
        # Retain all evidence and raw XML referenced by ANY retained case, including closed cases.
        c.execute("DELETE FROM alerts WHERE status='Closed' AND last_time<?",(cutoff('alert_retention_days'),))
        c.execute('UPDATE events SET raw=NULL WHERE time<? AND id NOT IN (SELECT event_id FROM alert_evidence)',(cutoff('raw_retention_days'),))
        c.execute('DELETE FROM events WHERE time<? AND id NOT IN (SELECT event_id FROM alert_evidence)',(cutoff('event_retention_days'),))
        for table in ('health','heartbeats'): c.execute(f'DELETE FROM {table} WHERE received_at<?',(cutoff('health_retention_days'),))
        c.execute('DELETE FROM endpoint_sessions WHERE observed_at<?',(cutoff('health_retention_days'),))
        c.execute('DELETE FROM usb WHERE time<?',(cutoff('event_retention_days'),))
        # Process samples & snapshots retention (protecting instances linked to correlation_links)
        c.execute(
            "DELETE FROM process_samples WHERE sampled_at<? AND instance_key NOT IN "
            "(SELECT source_id FROM correlation_links WHERE source_type='process_instance' "
            "UNION SELECT target_id FROM correlation_links WHERE target_type='process_instance')",
            (cutoff('process_sample_retention_days'),)
        )
        c.execute(
            "DELETE FROM process_snapshots WHERE sampled_at<? AND id NOT IN (SELECT DISTINCT snapshot_id FROM process_samples)",
            (cutoff('process_sample_retention_days'),)
        )
        c.execute(
            "DELETE FROM process_lifecycle_events WHERE event_time<? AND instance_key NOT IN "
            "(SELECT source_id FROM correlation_links WHERE source_type='process_instance' "
            "UNION SELECT target_id FROM correlation_links WHERE target_type='process_instance')",
            (cutoff('process_lifecycle_retention_days'),)
        )
        c.execute(
            "DELETE FROM browser_navigations WHERE navigation_time<? AND id NOT IN "
            "(SELECT source_id FROM correlation_links WHERE source_type='browser_navigation')",
            (cutoff('browser_retention_days'),)
        )
        c.execute(
            "DELETE FROM browser_download_revisions WHERE observed_at<? AND download_id NOT IN "
            "(SELECT source_id FROM correlation_links WHERE source_type='browser_download' "
            "UNION SELECT target_id FROM correlation_links WHERE target_type='browser_download')",
            (cutoff('browser_retention_days'),)
        )
        c.execute(
            "DELETE FROM browser_downloads WHERE started_at<? AND id NOT IN "
            "(SELECT source_id FROM correlation_links WHERE source_type='browser_download' "
            "UNION SELECT target_id FROM correlation_links WHERE target_type='browser_download')",
            (cutoff('browser_retention_days'),)
        )
        # Transport receipts are retained 90 days; event-level identity also guards replays.
        c.execute('DELETE FROM inbox WHERE processed=1 AND received_at<?',(stamp(dt(now())-timedelta(days=90)),))
        c.execute('DELETE FROM sessions WHERE expires_at<?',(now(),))
        c.execute('DELETE FROM login_attempts WHERE until_time<?',(now(),))
        audit(c,'worker','retention',{'policy':s,'retained_case_evidence':'protected'})

class Worker:
    def __init__(self,db):
        self.db=db; self.stop=threading.Event(); self.thread=None; self.lockfile=None; self.error=None
    def start(self):
        p=self.db.path.with_suffix('.worker.lock'); self.lockfile=open(p,'a+b'); self.lockfile.seek(0)
        if p.stat().st_size==0: self.lockfile.write(b'0'); self.lockfile.flush()
        self.lockfile.seek(0)
        try:
            if os.name=='nt':
                import msvcrt; msvcrt.locking(self.lockfile.fileno(),msvcrt.LK_NBLCK,1)
            else:
                import fcntl; fcntl.flock(self.lockfile,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except OSError:
            self.lockfile.close(); self.lockfile=None; raise RuntimeError('Another worker holds this database. Run one Uvicorn process.')
        with self.db.tx() as c:
            c.execute("UPDATE jobs SET status='Failed',error='Worker restarted during job; rerun explicitly' WHERE status='Running'")
        self.thread=threading.Thread(target=self.run,name='admonitor-worker',daemon=True); self.thread.start()
    def run(self):
        last_housekeeping=0
        run_job=None; behavior_error=None
        try:
            from .behavior import run_job
        except Exception as exc:
            # e.g. scikit-learn DLL blocked by Windows Application Control; keep ingestion running.
            behavior_error='Behavior model unavailable: '+type(exc).__name__+': '+str(exc)[:160]
            LOG.error(behavior_error)
        while not self.stop.is_set():
            try:
                if time.monotonic()-last_housekeeping>3600:
                    retention(self.db); last_housekeeping=time.monotonic()
                busy=process_one(self.db); self.error=behavior_error
                if not busy and run_job: busy=run_job(self.db)
                if not busy: self.stop.wait(1)
            except Exception as exc:
                self.error=type(exc).__name__+': '+str(exc)[:200]; LOG.exception('Worker failed'); self.stop.wait(5)
    def close(self):
        self.stop.set()
        if self.thread: self.thread.join(timeout=20)
        if self.lockfile: self.lockfile.close()
