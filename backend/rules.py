from __future__ import annotations
import math
from datetime import timedelta
from zoneinfo import ZoneInfo
from .db import now, dt, stamp, js, obj, uid, digest, settings
from .normalize import canonical, scoped

RULES = [
 ('restricted','Restricted path access denied',['access_request','share_check'],{'paths':['C:\\ADMonitor-Demo\\HR','C:\\ADMonitor-Demo\\Finance','C:\\ADMonitor-Demo\\IT','C:\\ADMonitor-Demo\\Management','C:\\ADMonitor-Demo\\Sensitive','C:\\ADMonitor-Demo\\Disposable'],'threshold':1}),
 ('bulk','Bulk sensitive file reads',['file_read'],{'threshold':10}),
 ('canary','Canary document accessed',['file_read'],{'paths':[]}),
 ('after_hours','After-hours sensitive activity',['file_read','file_write'],{}),
 ('staging','Dummy data staged into an archive',['file_copy','archive_create'],{'threshold':5}),
 ('usb_copy','Copy to removable storage observed',['file_copy'],{}),
 ('download_execute','Downloaded script activity correlated',['download','script_block','process_start'],{}),
 ('downloads','Measured download volume',['download'],{'threshold':10485760}),
 ('rapid_change','Rapid file modifications',['file_write','file_change','file_rename'],{'threshold':15,'paths':['C:\\ADMonitor-Scratch']}),
 ('non_primary','Sensitive access from non-primary device',['file_read','share_check'],{}),
 ('antivirus','Windows Defender detection',['antivirus_detection'],{'severity':'High'}),
 ('privilege_attack','Privileged Group Membership Modified',['privilege_change','share_check'],{'severity':'High'}),
 ('c2_beacon','Possible periodic outbound activity',['network_connection','observation'],{'severity':'Medium','threshold':5,'window_seconds':60}),
 ('suspicious_powershell','Suspicious / Obfuscated PowerShell Execution',['script_block','process_start'],{'severity':'High'}),
 ('failed_logon','Failed sign-in / wrong password attempts',['sign_in'],{'severity':'Medium','threshold':1,'window_seconds':300}),
 ('sustained_resource','Sustained process resource usage review',['process_resource'],{'severity':'Low','threshold':80,'window_seconds':60}),
 ('script_download_review','Script or executable download policy review',['download'],{'severity':'Medium','threshold':1,'window_seconds':300}),
 ('domain_policy','Configured lab domain policy match',['domain_policy'],{'severity':'Medium','threshold':1,'window_seconds':300,'paths':[]}),
]

def seed_rules(c):
    for key,name,required,extra in RULES:
        cfg={'threshold':1,'window_seconds':300,'cooldown_seconds':600,'severity':'Medium','paths':[], 'employee_sids':[], 'device_ids':[], **extra}
        c.execute('INSERT OR IGNORE INTO rules VALUES(?,?,1,1,?,?,?)',(key,name,js(cfg),js(required),now()))
        c.execute('INSERT OR IGNORE INTO rule_versions VALUES(?,1,?,1,?,?)',(key,js(cfg),'system',now()))
    c.execute("UPDATE rules SET name='Possible periodic outbound activity' WHERE id='c2_beacon' AND name='Command & Control (C2) Periodic Beaconing'")

def after_hours(time, policy):
    local=dt(time).astimezone(ZoneInfo(policy['timezone']))
    start,end=policy['business_start'],policy['business_end']
    inside=(start<=local.hour<end) if start<end else (local.hour>=start or local.hour<end)
    return local.weekday() not in policy['business_days'] or not inside

def window(c, e, seconds, categories):
    # SID preferred; when absent, source+account is an explicitly weaker grouping.
    who=e['user_sid'] or e['account']
    if not who: return [e]
    field='user_sid' if e['user_sid'] else 'account'
    rows=c.execute(f"SELECT * FROM events WHERE {field}=? AND time>=? AND time<=? AND category IN ({','.join('?' for _ in categories)}) ORDER BY time,id LIMIT 10001",
        (who,stamp(dt(e['time'])-timedelta(seconds=seconds)),e['time'],*categories)).fetchall()
    if len(rows)>10000: raise ValueError('Rule window exceeds 10000 records; shorten the configured window')
    return [dict(r) for r in rows]

def emit(c, rule, e, evidence, detail, observed, policy):
    cfg=obj(rule['config']); actor=e['user_sid'] or e['account'] or e['source_computer']
    bucket=math.floor(dt(e['time']).timestamp()/cfg['cooldown_seconds'])
    fingerprint=digest(js([rule['id'],rule['version'],actor,bucket]))
    explanation={'observed':observed,'threshold':cfg['threshold'],'window_seconds':cfg['window_seconds'],
        'detail':detail,'attribution':e['attribution'],'late_seconds':e['late_seconds'],
        'evidence_count':len(evidence),'grouping':'Fixed event-time cooldown bucket; adjacent buckets can produce separate alerts.'}
    if rule['id']=='failed_logon': title=f"Failed sign-in / wrong password ({observed} attempt{'s' if observed!=1 else ''})"
    elif rule['id']=='usb_copy':
        paths=[]
        for x in evidence:
            p=x.get('object_path') or obj(x.get('fields')).get('destination_path')
            if p and p not in paths: paths.append(str(p))
        if len(paths)==1:
            title=f"File pasted / transferred to USB pen drive ({paths[0]})"
        elif len(paths)>1:
            short_names=', '.join(p.split('\\')[-1] for p in paths[:3])
            drv=paths[0][:2] if len(paths[0])>=2 and paths[0][1]==':' else 'USB'
            title=f"Files pasted / transferred to USB pen drive {drv} ({observed} files: {short_names})"
        else:
            title=f"File pasted / transferred to USB pen drive ({observed} file{'s' if observed!=1 else ''})"
    else: title=rule['name']
    sev=('High' if observed>=3 else cfg['severity']) if rule['id']=='failed_logon' else cfg['severity']
    old=c.execute('SELECT id FROM alerts WHERE fingerprint=?',(fingerprint,)).fetchone()
    aid=old['id'] if old else uid()
    if not old:
        c.execute('INSERT INTO alerts(id,fingerprint,kind,rule_id,rule_version,title,severity,user_sid,account,device_id,first_time,last_time,created_at,explanation,config_snapshot) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
            (aid,fingerprint,'rule',rule['id'],rule['version'],title,sev,e['user_sid'],e['account'],e['access_device_id'] or e['device_id'],min(x['time'] for x in evidence),e['time'],now(),js(explanation),js({'rule':cfg,'policy':policy})))
    else:
        c.execute('UPDATE alerts SET title=?,severity=?,first_time=MIN(first_time,?),last_time=MAX(last_time,?),explanation=? WHERE id=?',
                  (title,sev,min(x['time'] for x in evidence),e['time'],js(explanation),aid))
    for ev in evidence:
        c.execute('INSERT OR IGNORE INTO alert_evidence VALUES(?,?)',(aid,ev['id']))
    return aid

def evaluate(c,e,only_rule=None):
    policy=settings(c)
    for rule in c.execute('SELECT * FROM rules WHERE enabled=1').fetchall():
        if only_rule and rule['id']!=only_rule: continue
        cfg=obj(rule['config']); key=rule['id']; needed=obj(rule['required'])
        if e['category'] not in needed: continue
        if cfg['employee_sids'] and e['user_sid'] not in cfg['employee_sids']: continue
        if cfg['device_ids'] and (e['access_device_id'] or e['device_id']) not in cfg['device_ids']: continue
        roots=cfg['paths'] or policy['sensitive_paths']; is_sensitive=scoped(e['canonical_path'],roots)
        evidence=[e]; count=1; detail=None
        if key=='restricted' and e['result']=='denied' and is_sensitive:
            detail='Windows audit failure on a configured restricted path; policy context does not imply malicious intent.'
        elif key=='canary' and cfg['paths'] and e['canonical_path'] in [canonical(p) for p in cfg['paths']]:
            detail='ReadData/ListDirectory was used on the exact configured canary path. Confirm that the path is a file.'
        elif key=='after_hours' and is_sensitive and after_hours(e['time'],policy):
            detail=f"Sensitive activity outside configured business hours in {policy['timezone']}."
        elif key in ('bulk','rapid_change','downloads'):
            evidence=window(c,e,cfg['window_seconds'],needed)
            if key!='downloads': evidence=[v for v in evidence if scoped(v['canonical_path'],roots)]
            if key=='downloads': count=sum(obj(v['fields']).get('bytes',0) for v in evidence)
            else: count=len({v['canonical_path'] for v in evidence if v['canonical_path']})
            if count>=cfg['threshold']:
                detail=('Measured bytes from the instrumented downloader; no claim about other browser/network traffic.' if key=='downloads' else 'Distinct observed paths in the event-time window; repeated accesses to one path count once. File-vs-directory requires source context.')
        elif key=='staging' and e['category']=='archive_create':
            fields=obj(e['fields']); folder=canonical(fields.get('staging_directory'))
            evidence=[v for v in window(c,e,cfg['window_seconds'],['file_copy']) if folder and scoped(v['canonical_path'],[folder])]+[e]
            count=len({v['canonical_path'] for v in evidence if v['category']=='file_copy'})
            if count>=cfg['threshold']: detail='Successful instrumented copies followed by measured archive creation in the same staging folder. This does not prove exfiltration.'
        elif key=='usb_copy':
            f=obj(e['fields']) if isinstance(e.get('fields'),(str,bytes)) else (e.get('fields') or {})
            dest=f.get('destination_path') or e.get('object_path') or e.get('canonical_path') or ''
            is_usb=f.get('destination_removable') or any(str(dest).upper().startswith(f"{d}:") for d in "DEFGHIJKLMNOPQRSTUVWXYZ") or 'removable' in str(f).casefold()
            if is_usb and (f.get('source_path') or is_sensitive or e['category'] in ('file_copy','file_write')):
                raw_ev=window(c,e,cfg['window_seconds'],['file_copy'])
                if not any(v['id']==e['id'] for v in raw_ev): raw_ev.append(e)
                dedup={}
                for v in raw_ev:
                    vf=obj(v.get('fields')) if isinstance(v.get('fields'),(str,bytes)) else (v.get('fields') or {})
                    vp=str(v.get('object_path') or vf.get('destination_path') or v['id']).casefold()
                    dedup[vp]=v
                evidence=list(dedup.values())
                count=len(evidence)
                sz=f.get('bytes')
                sz_str=f" ({sz} bytes)" if sz else ""
                detail=f"File pasted / transferred directly onto external USB pen drive (Destination on pen drive: {dest}{sz_str}; {count} distinct file(s) pasted in {cfg['window_seconds']}s window). Normal file copies or moves inside the PC (C:) are ignored."
        elif key=='privilege_attack' and e['category'] in ('privilege_change','share_check'):
            f=obj(e['fields']) if isinstance(e.get('fields'),(str,bytes)) else (e.get('fields') or {})
            if e['category']=='privilege_change':
                target_group=(f.get('TargetUserName') or f.get('TargetSid') or f.get('target_group') or e.get('object_path') or '')
                member=(f.get('MemberName') or f.get('MemberSid') or f.get('member') or f.get('TargetUserName') or e.get('account') or 'unknown-member')
                priv_groups=['administrators','domain admins','enterprise admins','schema admins','account operators','backup operators','server operators']
                if any(pg in str(target_group).casefold() for pg in priv_groups):
                    detail=f"High-privilege group membership change detected: {member} added to privileged group {target_group}."
            elif str(f.get('RelativeTargetName') or '').casefold()=='samr':
                acct=str(e.get('account') or '').strip()
                if acct and not acct.endswith('$') and 'administrator' not in acct.casefold():
                    detail=f"Active Directory SAMR (\\\\PIPE\\\\samr) privileged group modification / enumeration RPC invoked over IPC$ by {acct} from workstation {e.get('source_address') or 'unknown-source'} (e.g., net group \"Domain Admins\" /domain)."
        elif key=='c2_beacon':
            f=obj(e['fields']) if isinstance(e.get('fields'),(str,bytes)) else (e.get('fields') or {})
            dest=f.get('c2_destination') or f.get('remote_ip') or f.get('destination') or 'external host'
            agg_count=int(f.get('connection_count') or f.get('pulse_count') or 0)
            if agg_count>=cfg['threshold']:
                count=agg_count
                interval=f.get('interval_seconds') or 3
                jitter=f.get('jitter_percent',0)
                detail=f"Possible periodic outbound activity: {count} aggregated connections to {dest} within {cfg['window_seconds']}s (~{interval}s intervals, {jitter}% jitter). Pattern warrants inspection of originating process and destination."
                evidence=[e]
            else:
                conns=window(c,e,cfg['window_seconds'],['network_connection'])
                matching=[v for v in conns if (obj(v['fields']).get('c2_destination') or obj(v['fields']).get('remote_ip'))==dest] or conns
                count=len(matching)
                if count>=cfg['threshold']:
                    evidence=matching
                    interval=f.get('interval_seconds') or 3
                    jitter=f.get('jitter_percent',0)
                    detail=f"Possible periodic outbound activity: {count} observed connections to {dest} within {cfg['window_seconds']}s (~{interval}s intervals, {jitter}% jitter). Pattern warrants inspection of originating process and destination."
        elif key=='suspicious_powershell' and e['category'] in ('script_block','process_start'):
            cmd=(e.get('command_line') or '').casefold()
            f=obj(e.get('fields')) if isinstance(e.get('fields'),(str,bytes)) else (e.get('fields') or {})
            script_text=((f.get('ScriptBlockText') or '') if isinstance(f,dict) else '').casefold()
            combined=f"{cmd} {script_text}"
            if 'ad monitor - windows vm endpoint monitoring agent' not in combined:
                suspicious=['-enc ','-encodedcommand','frombase64string','downloadstring','invoke-expression','iex(','iex (','iex ','net.webclient','bypass','mimikatz','sekurlsa','amsiutils','token::elevate','whoami /priv']
                hits=[s for s in suspicious if s in combined] or (f.get('heuristics_matched') if isinstance(f,dict) else None) or []
                if hits:
                    detail=f"Suspicious / obfuscated PowerShell execution matched threat heuristics: {', '.join(str(x) for x in hits)}."
        elif key=='download_execute' and e['category'] in ('script_block','process_start'):
            downloads=window(c,e,cfg['window_seconds'],['download'])
            for v in downloads:
                path=canonical(obj(v['fields']).get('destination_path'))
                if path and ((e['category']=='script_block' and e['canonical_path']==path) or canonical(e['process_path'])==path):
                    evidence=[v,e]; detail='Measured download followed by script-block evidence at that exact path or direct process image execution. Time/path correlation does not establish intent.'; break
        elif key=='non_primary' and is_sensitive:
            target=e['access_device_id']
            primary=c.execute('SELECT device_id FROM associations WHERE employee_sid=? AND is_primary=1',(e['user_sid'],)).fetchall()
            if target and e['attribution'].startswith('Strong:') and primary and target not in [r['device_id'] for r in primary]:
                detail='Client identity resolved using a same-host logon session and explicit workstation; differs from administrator-configured primary device.'
        elif key=='antivirus': detail='Actual Windows Defender detection event. Review threat metadata and subsequent remediation events.'
        elif key=='failed_logon' and e['category']=='sign_in' and e['result']=='denied':
            acct=(e.get('account') or '').strip()
            low_acct=acct.casefold()
            if acct and not acct.endswith('$') and not any(x in low_acct for x in ('anonymous','dwm-','umfd-','local service','network service','system')):
                evidence=[v for v in window(c,e,cfg['window_seconds'],['sign_in']) if v['result']=='denied']
                if not any(v['id']==e['id'] for v in evidence): evidence.append(e)
                count=len(evidence)
                if count>=cfg['threshold']:
                    f=obj(e.get('fields')) if isinstance(e.get('fields'),(str,bytes)) else (e.get('fields') or {})
                    sub=str(f.get('SubStatus') or f.get('FailureCode') or f.get('Status') or '').strip().lower()
                    reason='wrong password entered' if sub in ('0xc000006a','0x18','0xc000006d') else ('account locked out' if sub in ('0xc0000234','0x12') or e.get('event_id')==4740 else 'authentication failure')
                    eid_label=f"Event {e['event_id']}" if e.get('event_id') else 'Endpoint authentication monitor'
                    detail=f"Wrong password / failed sign-in counter: {count} failed attempt(s) observed for {acct} within {cfg['window_seconds']}s window (Latest reason: {reason}, {eid_label})."
        if detail: emit(c,rule,e,evidence,detail,count,policy)

def evaluate_with_late(c,e):
    evaluate(c,e)
    # Re-evaluate later anchors whose windows can include this late-arriving event.
    maximum=max([obj(r['config'])['window_seconds'] for r in c.execute('SELECT config FROM rules WHERE enabled=1')],default=0)
    identity=e['user_sid'] or e['account']
    if identity:
        field='user_sid' if e['user_sid'] else 'account'
        anchors=c.execute(f'SELECT * FROM events WHERE {field}=? AND time>? AND time<=? ORDER BY time LIMIT 1001',
            (identity,e['time'],stamp(dt(e['time'])+timedelta(seconds=maximum)))).fetchall()
        if len(anchors)>1000: raise ValueError('Late-event re-evaluation exceeds 1000 anchors; use bounded administrative replay')
        for anchor in anchors: evaluate(c,dict(anchor))

def readiness(c,rule):
    cfg=obj(rule['config']); categories=obj(rule['required'])
    cutoff_7d=stamp(dt(now())-timedelta(days=7))
    seen={r['category'] for r in c.execute('SELECT DISTINCT category FROM events WHERE time>=?',(cutoff_7d,))}
    if not rule['enabled']: return {'state':'Disabled','ready':False,'missing':[]}
    missing=[v for v in categories if v not in seen]
    if rule['id']=='download_execute':
        has_dl='download' in seen or bool(c.execute("SELECT 1 FROM browser_downloads WHERE state='completed' AND started_at>=? LIMIT 1",(cutoff_7d,)).fetchone())
        missing=[] if has_dl else ['download']
        has_proc={'script_block','process_start'}&seen or bool(c.execute("SELECT 1 FROM process_instances WHERE first_seen_at>=? LIMIT 1",(cutoff_7d,)).fetchone())
        if not has_proc: missing.append('script_block or process_start')
    elif rule['id']=='sustained_resource':
        has_samples=bool(c.execute('SELECT 1 FROM process_samples WHERE sampled_at>=? LIMIT 1',(cutoff_7d,)).fetchone())
        missing=[] if has_samples else ['process_snapshot_samples']
    elif rule['id']=='script_download_review':
        has_dl='download' in seen or bool(c.execute("SELECT 1 FROM browser_downloads WHERE started_at>=? LIMIT 1",(cutoff_7d,)).fetchone())
        missing=[] if has_dl else ['browser_download']
    elif rule['id']=='domain_policy':
        has_nav=bool(c.execute('SELECT 1 FROM browser_navigations WHERE navigation_time>=? LIMIT 1',(cutoff_7d,)).fetchone())
        policy_domains=cfg.get('paths') or settings(c).get('restricted_domains') or []
        missing=[] if has_nav else ['browser_navigation']
        if not policy_domains: missing.append('configured restricted_domains policy list')
    elif rule['id']=='suspicious_powershell':
        missing=[] if {'script_block','process_start'}&seen else list(categories)
    elif rule['id']=='c2_beacon':
        missing=[] if 'network_connection' in seen else ['network_connection']
    elif rule['id']=='restricted':
        missing=[] if {'access_request','share_check'}&seen else list(categories)
    elif rule['id']=='after_hours':
        missing=[] if {'file_read','file_write'}&seen else list(categories)
    elif rule['id']=='rapid_change':
        missing=[] if {'file_write','file_change','file_rename'}&seen else list(categories)
    if rule['id']=='canary' and not cfg['paths']: missing.append('configured exact canary path')
    if rule['id']=='non_primary' and not c.execute('SELECT 1 FROM associations WHERE is_primary=1').fetchone(): missing.append('explicit primary device and strong client attribution')
    return {'state':'Not ready' if missing else 'Telemetry observed','ready':not bool(missing),'missing':missing,'note':'Recent telemetry presence does not verify audit-policy coverage.'}
