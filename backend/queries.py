from __future__ import annotations
from datetime import timedelta
from fastapi import HTTPException
from .db import now,dt,stamp,js,obj,row,presence,settings

EVENT_LIST='e.id,e.time,e.received_at,e.event_id,e.provider,e.channel,e.source_computer,e.collector_id,e.user_sid,e.account,e.device_id,e.access_device_id,e.attribution,e.category,e.result,e.object_path,e.source_address,e.evidence_type,e.late_seconds'

def period(params,default_hours=24):
    try:
        start=stamp(params.get('start') or dt(now())-timedelta(hours=default_hours)); end=stamp(params.get('end') or now())
        if start>end: raise ValueError('Start must precede end')
        if (dt(end)-dt(start)).days>366: raise ValueError('Maximum query period is 366 days')
        return start,end
    except (ValueError,TypeError) as exc: raise HTTPException(422,str(exc))

def event_filter(params):
    start,end=period(params); clauses=['e.time>=?','e.time<=?']; values=[start,end]
    for key,col in [('user_sid','user_sid'),('event_id','event_id'),('provider','provider'),('channel','channel'),('category','category'),('result','result')]:
        if params.get(key): clauses.append('e.'+col+'=?'); values.append(params[key])
    if params.get('device_id'): clauses.append('(e.device_id=? OR e.access_device_id=?)'); values.extend([params['device_id']]*2)
    for key,col in [('path','object_path'),('q','account')]:
        if params.get(key):
            pattern='%'+params[key].replace('\\','\\\\').replace('%','\\%').replace('_','\\_')[:200]+'%'
            if key=='q': clauses.append("(e.account LIKE ? ESCAPE '\' OR e.source_computer LIKE ? ESCAPE '\' OR e.object_path LIKE ? ESCAPE '\')"); values.extend([pattern]*3)
            else: clauses.append("e."+col+" LIKE ? ESCAPE '\'"); values.append(pattern)
    if params.get('severity'):
        clauses.append('EXISTS (SELECT 1 FROM alert_evidence ae JOIN alerts a ON a.id=ae.alert_id WHERE ae.event_id=e.id AND a.severity=?)'); values.append(params['severity'])
    return ' AND '.join(clauses),values

def pagination(params):
    try: page=max(1,int(params.get('page',1))); size=min(500,max(1,int(params.get('page_size',25))))
    except ValueError: raise HTTPException(422,'Invalid pagination')
    if page>100000: raise HTTPException(422,'Page too large')
    return page,size

def events(c,params,export=False):
    clause,values=event_filter(params); page,size=pagination(params)
    total=c.execute('SELECT COUNT(*) FROM events e WHERE '+clause,values).fetchone()[0]
    limit=10000 if export else size; offset=0 if export else (page-1)*size
    rows=c.execute('SELECT '+EVENT_LIST+' FROM events e WHERE '+clause+' ORDER BY e.time DESC,e.id LIMIT ? OFFSET ?',(*values,limit,offset)).fetchall()
    return {'items':[dict(r) for r in rows],'total':total,'page':page,'page_size':limit,'truncated':export and total>limit}

def alert_filter(params):
    start,end=period(params, default_hours=8760 if params.get('rule_id') else 24); q=['a.last_time>=?','a.first_time<=?']; args=[start,end]
    for key in ('severity','status','kind','user_sid','device_id','rule_id'):
        if params.get(key): q.append('a.'+key+'=?'); args.append(params[key])
    return ' AND '.join(q),args

def alerts(c,params):
    clause,args=alert_filter(params); page,size=pagination(params)
    count=c.execute('SELECT COUNT(*) FROM alerts a WHERE '+clause,args).fetchone()[0]
    data=c.execute('SELECT a.* FROM alerts a WHERE '+clause+' ORDER BY a.last_time DESC,a.id LIMIT ? OFFSET ?',(*args,size,(page-1)*size)).fetchall()
    return {'items':[decode_alert(r) for r in data],'total':count,'page':page,'page_size':size}

def decode_alert(r):
    d=dict(r); d['explanation']=obj(d['explanation']); d['config_snapshot']=obj(d['config_snapshot']); return d

def device(r):
    d=dict(r); d['ips']=obj(d['ips']); d['errors']=obj(d['errors']); d['presence']=presence(d['last_heartbeat']); return d

def overview(c,params):
    clause,args=event_filter(params); ac,aa=alert_filter(params); start,end=period(params)
    devices=[device(r) for r in c.execute('SELECT * FROM devices ORDER BY hostname')]
    if params.get('device_id'): devices=[d for d in devices if d['id']==params['device_id']]
    counts={p:sum(d['presence']==p for d in devices) for p in ('Online','Stale','Offline','Unknown')}
    severity={r['severity']:r['n'] for r in c.execute("SELECT a.severity,COUNT(*) n FROM alerts a WHERE "+ac+" AND a.status!='Closed' GROUP BY a.severity",aa)}
    buckets=[dict(r) for r in c.execute("SELECT substr(e.time,1,13)||':00:00Z' time,COUNT(*) count FROM events e WHERE "+clause+' GROUP BY substr(e.time,1,13) ORDER BY time',args)]
    health=[]
    for dev in devices[:12]:
        h=row(c.execute('SELECT * FROM health WHERE device_id=? ORDER BY received_at DESC LIMIT 1',(dev['id'],)).fetchone())
        if h: h['disks']=obj(h['disks'])
        health.append({'device':dev,'health':h})
    interests=[dict(r) for r in c.execute("SELECT a.user_sid,a.account,a.device_id,COUNT(*) open_alerts,GROUP_CONCAT(DISTINCT a.title) reasons FROM alerts a WHERE "+ac+" AND a.status!='Closed' GROUP BY COALESCE(a.user_sid,a.account,a.device_id) ORDER BY open_alerts DESC LIMIT 6",aa)]
    recent=alerts(c,{**dict(params),'page_size':'5','page':'1'})['items']
    usbwhere='time>=? AND time<=?'; usbargs=[start,end]
    if params.get('device_id'): usbwhere+=' AND device_id=?'; usbargs.append(params['device_id'])
    emp_observed = c.execute("SELECT COUNT(DISTINCT COALESCE(e.user_sid, e.account)) FROM events e WHERE "+clause+" AND (e.user_sid IS NOT NULL OR e.account IS NOT NULL)", args).fetchone()[0]
    dir_count = c.execute("SELECT COUNT(*) FROM employees").fetchone()[0]
    cols = [dict(r) for r in c.execute("SELECT id, name, kind, expected_host, enabled, last_seen, last_ingest FROM collectors WHERE enabled=1").fetchall()]
    wef_cs = [col for col in cols if col['kind'] in ('wef', 'bridge')]
    wef_c = max(wef_cs, key=lambda x: x['last_seen'] or '') if wef_cs else None
    end_cs = [col for col in cols if col['kind'] == 'endpoint']
    browser_cs = [col for col in cols if col['kind'] == 'browser']
    last_sync = c.execute("SELECT MAX(synced_at) FROM employees").fetchone()[0]
    active_m = c.execute("SELECT COUNT(*) FROM models WHERE active=1").fetchone()[0]
    ev_total = c.execute('SELECT COUNT(*) FROM events e WHERE '+clause,args).fetchone()[0]
    open_total = sum(severity.values())
    return {
        'period':{'start':start,'end':end},
        'event_count':ev_total,
        'open_alerts':open_total,
        'severity':severity,
        'device_count':len(devices),
        'presence':counts,
        'metrics':{
            'open_alerts':open_total,
            'open_alerts_by_severity':{'High':severity.get('High',0),'Medium':severity.get('Medium',0),'Low':severity.get('Low',0)},
            'monitored_devices':len(devices),
            'online_devices':counts.get('Online',0),
            'presence_counts':counts,
            'events_today':ev_total,
        },
        'volume':buckets,
        'recent_alerts':recent,
        'recent_events':events(c,{**dict(params),'page_size':'8','page':'1'})['items'],
        'interests':interests,
        'device_health':health,
        'usb_count':c.execute('SELECT COUNT(*) FROM usb WHERE '+usbwhere,usbargs).fetchone()[0],
        'employees_observed': emp_observed,
        'directory_count': dir_count,
        'collectors_summary': {
            'wef': {'connected': bool(wef_c and wef_c['last_seen'] and presence(wef_c['last_seen']) in ('Online', 'Stale')), 'presence': presence(wef_c['last_seen']) if wef_c and wef_c['last_seen'] else 'Unknown', 'last_seen': wef_c['last_seen'] if wef_c else None},
            'endpoints': {'total': max(len(end_cs), 1), 'reporting': sum(1 for ec in end_cs if ec['last_seen'] and presence(ec['last_seen']) in ('Online', 'Stale')), 'last_seen': max((ec['last_seen'] for ec in end_cs if ec['last_seen']), default=None)},
            'browser': {'total': len(browser_cs), 'reporting': sum(1 for bc in browser_cs if bc['last_seen'] and presence(bc['last_seen']) in ('Online', 'Stale')), 'last_seen': max((bc['last_seen'] for bc in browser_cs if bc['last_seen']), default=None)},
            'directory_sync': {'last_sync': last_sync}
        },
        'uba_state': 'Model active' if active_m else 'Collecting baseline',
        'collection':{'configured':c.execute('SELECT COUNT(*) FROM collectors WHERE enabled=1').fetchone()[0],
            'last_ingest':c.execute('SELECT MAX(last_ingest) FROM collectors').fetchone()[0],
            'pending':c.execute('SELECT COUNT(*) FROM inbox WHERE processed=0').fetchone()[0],
            'quarantined':c.execute('SELECT COUNT(*) FROM inbox WHERE processed=-1').fetchone()[0]}
    }

def _snapshot_freshness(observed_at: str | None) -> tuple[str, float | None]:
    if not observed_at:
        return 'No snapshot received', None
    age = max(0.0, round((dt(now()) - dt(observed_at)).total_seconds(), 1))
    if age <= 35:
        return 'Fresh', age
    if age <= 95:
        return 'Stale', age
    return 'Collector idle / disconnected', age

def processes_view(c, params):
    start, end = period(params, default_hours=int(params.get('hours', 24)))
    page, size = pagination(params)
    mode = (params.get('mode') or 'live').strip().casefold()
    device_id = params.get('device_id')
    user_sid = params.get('user_sid')
    state_filter = (params.get('state') or '').strip()
    if state_filter.casefold() == 'all':
        state_filter = ''
        mode = 'history'
    sig_filter = params.get('signature_state')
    search = (params.get('q') or params.get('search') or '').strip()
    sort_by = (params.get('sort_by') or 'cpu').strip().casefold()

    # Latest snapshot metadata
    snap_q = "SELECT ps.*, d.hostname FROM process_snapshots ps LEFT JOIN devices d ON d.id=ps.device_id WHERE 1=1"
    snap_args = []
    if device_id:
        snap_q += " AND ps.device_id=?"
        snap_args.append(device_id)
    snap_q += " ORDER BY ps.sampled_at DESC LIMIT 1"
    latest_snap_row = c.execute(snap_q, snap_args).fetchone()
    latest_snap = None
    if latest_snap_row:
        latest_snap = dict(latest_snap_row)
        latest_snap['observed_at'] = latest_snap['sampled_at']
        latest_snap['errors'] = obj(latest_snap['errors'])
        latest_snap['is_complete'] = bool(latest_snap['is_complete'])
        latest_snap['complete'] = bool(latest_snap['is_complete'])
        fresh_label, age_s = _snapshot_freshness(latest_snap['sampled_at'])
        latest_snap['freshness'] = fresh_label
        latest_snap['age_seconds'] = age_s

    clauses = ['1=1']
    args = []
    if mode == 'live':
        if latest_snap and device_id:
            # Show processes observed in the latest snapshot for this device, or currently marked Observed
            clauses.append("(pi.observed_state='Observed' OR pi.last_seen_at>=?)")
            args.append(stamp(dt(latest_snap['sampled_at']) - timedelta(seconds=20)))
        elif not state_filter:
            clauses.append("pi.observed_state='Observed'")
    elif params.get('state', '').casefold() != 'all':
        clauses.append("pi.last_seen_at>=? AND pi.first_seen_at<=?")
        args.extend([start, end])

    if device_id:
        clauses.append("pi.device_id=?")
        args.append(device_id)
    if user_sid:
        clauses.append("pi.user_sid=?")
        args.append(user_sid)
    if state_filter:
        clauses.append("pi.observed_state=?")
        args.append(state_filter)
    if sig_filter:
        clauses.append("pi.signature_state=?")
        args.append(sig_filter)
    if params.get('correlated_only') in ('1', 'true', 'True'):
        clauses.append(
            "EXISTS (SELECT 1 FROM correlation_links cl WHERE "
            "(cl.source_type='process_instance' AND cl.source_id=pi.instance_key) OR "
            "(cl.target_type='process_instance' AND cl.target_id=pi.instance_key))"
        )
    if search:
        pat = f"%{search[:200]}%"
        clauses.append(
            "(pi.name LIKE ? OR COALESCE(pi.executable_path,'') LIKE ? OR COALESCE(pi.command_line,'') LIKE ? "
            "OR COALESCE(pi.account,'') LIKE ? OR CAST(pi.pid AS TEXT) LIKE ?)"
        )
        args.extend([pat] * 5)

    where_sql = ' AND '.join(clauses)
    total = c.execute(f"SELECT COUNT(*) FROM process_instances pi WHERE {where_sql}", args).fetchone()[0]

    # Fetch rows with latest sample metrics
    rows = c.execute(
        f"""
        SELECT pi.*, d.hostname,
               s.cpu_percent, s.cpu_time_ms, s.working_set_bytes, s.private_bytes, s.sampled_at AS latest_sample_at,
               (SELECT COUNT(*) FROM correlation_links cl WHERE (cl.source_type='process_instance' AND cl.source_id=pi.instance_key) OR (cl.target_type='process_instance' AND cl.target_id=pi.instance_key)) AS correlation_count,
               (SELECT cl.case_key FROM correlation_links cl WHERE (cl.source_type='process_instance' AND cl.source_id=pi.instance_key) OR (cl.target_type='process_instance' AND cl.target_id=pi.instance_key) ORDER BY CASE cl.confidence WHEN 'High' THEN 3 WHEN 'Medium' THEN 2 ELSE 1 END DESC LIMIT 1) AS correlated_case_key
        FROM process_instances pi
        LEFT JOIN devices d ON d.id = pi.device_id
        LEFT JOIN process_samples s ON s.id = (
            SELECT ps2.id FROM process_samples ps2 WHERE ps2.instance_key = pi.instance_key ORDER BY ps2.sampled_at DESC LIMIT 1
        )
        WHERE {where_sql}
        """,
        args
    ).fetchall()

    app_catalog = {
        'msedge.exe': 'Microsoft Edge',
        'chrome.exe': 'Google Chrome',
        'firefox.exe': 'Mozilla Firefox',
        'brave.exe': 'Brave Browser',
        'powershell.exe': 'Windows PowerShell',
        'pwsh.exe': 'PowerShell Core',
        'cmd.exe': 'Command Prompt',
        'windowsterminal.exe': 'Windows Terminal',
        'openconsole.exe': 'Windows Terminal Console',
        'explorer.exe': 'File Explorer',
        'systemsettings.exe': 'Windows Settings',
        'notepad.exe': 'Notepad',
        'taskmgr.exe': 'Task Manager',
        'calc.exe': 'Calculator',
        'calculatorapp.exe': 'Calculator',
        'mspaint.exe': 'Paint',
        'code.exe': 'Visual Studio Code',
        'winword.exe': 'Microsoft Word',
        'excel.exe': 'Microsoft Excel',
        'powerpnt.exe': 'Microsoft PowerPoint',
        'onedrive.exe': 'Microsoft OneDrive',
        'teams.exe': 'Microsoft Teams',
        'ms-teams.exe': 'Microsoft Teams',
        'slack.exe': 'Slack',
        'widgets.exe': 'Windows Widgets',
        'mmc.exe': 'Microsoft Management Console',
        'regedit.exe': 'Registry Editor',
        'mstsc.exe': 'Remote Desktop Connection',
        'python.exe': 'Python Interpreter',
        'node.exe': 'Node.js Runtime',
    }
    bg_system_in_user_session = {
        'csrss.exe', 'winlogon.exe', 'dwm.exe', 'fontdrvhost.exe', 'sihost.exe',
        'svchost.exe', 'taskhostw.exe', 'runtimebroker.exe', 'ctfmon.exe',
        'textinputhost.exe', 'startmenuexperiencehost.exe', 'searchhost.exe',
        'shellexperiencehost.exe', 'applicationframehost.exe', 'conhost.exe',
        'dllhost.exe', 'backgroundtaskhost.exe', 'securityhealthsystray.exe',
        'vm3dservice.exe', 'vmtoolsd.exe', 'tabtip.exe', 'crossdeviceresume.exe',
        'widgetservice.exe', 'msedgewebview2.exe', 'smartscreen.exe',
    }

    items = []
    for r in rows:
        item = dict(r)
        item['source_event_ids'] = obj(item['source_event_ids'])
        item['raw_metadata'] = obj(item['raw_metadata'])
        item['cpu_display'] = f"{item['cpu_percent']:.1f}%" if item.get('cpu_percent') is not None else 'Unavailable (first sample)'
        low_name = (item.get('name') or '').strip().casefold()
        sess_id = int(item.get('session_id') or 0)
        raw_meta = item['raw_metadata'] if isinstance(item['raw_metadata'], dict) else {}
        win_title = str(raw_meta.get('window_title') or '').strip() or None
        is_app = (low_name in app_catalog) or bool(win_title) or (
            sess_id > 0
            and low_name not in bg_system_in_user_session
            and bool(item.get('account'))
            and not str(item.get('account') or '').upper().startswith(('NT AUTHORITY\\', 'WINDOW MANAGER\\', 'FONT DRIVER HOST\\'))
        )
        app_title = app_catalog.get(low_name) or win_title or (item.get('name') or 'Application').removesuffix('.exe').removesuffix('.EXE')
        item['is_running_app'] = bool(is_app)
        item['app_name'] = app_title if is_app else None
        item['window_title'] = win_title
        item['process_category'] = 'App' if is_app else ('Background' if sess_id > 0 else 'System')
        items.append(item)

    if sort_by == 'cpu':
        items.sort(key=lambda x: (x.get('cpu_percent') is not None, float(x.get('cpu_percent') or -1.0), x.get('working_set_bytes') or 0), reverse=True)
    elif sort_by == 'memory':
        items.sort(key=lambda x: (int(x.get('working_set_bytes') or -1), float(x.get('cpu_percent') or -1.0)), reverse=True)
    elif sort_by == 'pid':
        items.sort(key=lambda x: int(x.get('pid') or 0))
    elif sort_by == 'name':
        items.sort(key=lambda x: (x.get('name') or '').casefold())
    else:
        items.sort(
            key=lambda x: (
                1 if x.get('observed_state') == 'Observed' else 0,
                2 if x.get('is_running_app') else (1 if int(x.get('session_id') or 0) > 0 else 0),
                int(x.get('working_set_bytes') or 0),
                x.get('last_seen_at') or '',
            ),
            reverse=True,
        )

    # Build grouped running_apps list from observed user applications
    app_groups: dict[str, dict] = {}
    for x in items:
        if not x.get('is_running_app') or x.get('observed_state') != 'Observed':
            continue
        gkey = f"{x.get('device_id') or ''}:{(x.get('app_name') or x.get('name') or '').casefold()}"
        ws = int(x.get('working_set_bytes') or 0)
        cpu = float(x.get('cpu_percent') or 0.0) if x.get('cpu_percent') is not None else 0.0
        has_cpu = x.get('cpu_percent') is not None
        if gkey not in app_groups:
            app_groups[gkey] = {
                'app_name': x.get('app_name') or x.get('name'),
                'name': x.get('name'),
                'instance_key': x.get('instance_key'),
                'primary_pid': x.get('pid'),
                'pids': [x.get('pid')],
                'process_count': 1,
                'account': x.get('account') or x.get('user_sid') or 'Interactive user',
                'hostname': x.get('hostname'),
                'device_id': x.get('device_id'),
                'working_set_bytes': ws,
                'cpu_percent': cpu if has_cpu else None,
                '_has_cpu': has_cpu,
                '_max_ws': ws,
                'window_title': x.get('window_title'),
                'signature_state': x.get('signature_state'),
                'observed_state': 'Running',
                'last_seen_at': x.get('last_seen_at'),
            }
        else:
            grp = app_groups[gkey]
            grp['process_count'] += 1
            grp['pids'].append(x.get('pid'))
            grp['working_set_bytes'] += ws
            if has_cpu:
                grp['cpu_percent'] = float(grp['cpu_percent'] or 0.0) + cpu
                grp['_has_cpu'] = True
            if ws > grp['_max_ws']:
                grp['_max_ws'] = ws
                grp['instance_key'] = x.get('instance_key')
                grp['primary_pid'] = x.get('pid')
            if not grp.get('window_title') and x.get('window_title'):
                grp['window_title'] = x.get('window_title')

    running_apps = sorted(
        [
            {k: v for k, v in grp.items() if not k.startswith('_')}
            for grp in app_groups.values()
        ],
        key=lambda g: (int(g.get('working_set_bytes') or 0), int(g.get('process_count') or 0)),
        reverse=True,
    )

    # Summary KPIs across the filtered scope (before pagination)
    observed_count = sum(1 for x in items if x['observed_state'] == 'Observed')
    unique_exes = len({(x.get('canonical_path') or x.get('name') or '').casefold() for x in items if x.get('name')})
    unsigned_count = sum(1 for x in items if x.get('signature_state') == 'Unsigned')
    unverified_count = sum(1 for x in items if x.get('signature_state') not in ('Verified', 'Signed', 'Unsigned'))
    correlated_count = sum(1 for x in items if int(x.get('correlation_count') or 0) > 0)

    lc_where = "event_time>=? AND event_time<=?"
    lc_args = [start, end]
    if device_id:
        lc_where += " AND device_id=?"
        lc_args.append(device_id)
    lifecycle_total = c.execute(f"SELECT COUNT(*) FROM process_lifecycle_events WHERE {lc_where}", lc_args).fetchone()[0]

    paginated = items[(page - 1) * size : page * size]
    return {
        'period': {'start': start, 'end': end},
        'mode': mode,
        'latest_snapshot': latest_snap,
        'running_apps': running_apps,
        'summary': {
            'observed_processes': observed_count,
            'running_apps_count': len(running_apps),
            'total_matching_instances': total,
            'unique_executables': unique_exes,
            'unsigned_count': unsigned_count,
            'unverified_or_not_collected_count': unverified_count,
            'correlated_to_downloads': correlated_count,
            'lifecycle_events_count': lifecycle_total,
        },
        'items': paginated,
        'total': total,
        'page': page,
        'page_size': size,
    }

def process_lifecycle_history(c, params):
    start, end = period(params, default_hours=int(params.get('hours', 24)))
    page, size = pagination(params)
    clauses = ['ple.event_time>=?', 'ple.event_time<=?']
    args = [start, end]
    if params.get('device_id'):
        clauses.append('ple.device_id=?')
        args.append(params['device_id'])
    if params.get('user_sid'):
        clauses.append('ple.user_sid=?')
        args.append(params['user_sid'])
    if params.get('event_type'):
        clauses.append('ple.event_type=?')
        args.append(params['event_type'])
    if params.get('q'):
        pat = f"%{params['q'][:200]}%"
        clauses.append("(ple.name LIKE ? OR COALESCE(ple.executable_path,'') LIKE ? OR COALESCE(ple.command_line,'') LIKE ? OR COALESCE(ple.account,'') LIKE ?)")
        args.extend([pat] * 4)

    where_sql = ' AND '.join(clauses)
    total = c.execute(f"SELECT COUNT(*) FROM process_lifecycle_events ple WHERE {where_sql}", args).fetchone()[0]
    rows = c.execute(
        f"""
        SELECT ple.*, d.hostname, pi.parent_instance_key, pi.parent_name, pi.parent_confidence, pi.observed_state
        FROM process_lifecycle_events ple
        LEFT JOIN devices d ON d.id = ple.device_id
        LEFT JOIN process_instances pi ON pi.instance_key = ple.instance_key
        WHERE {where_sql}
        ORDER BY ple.event_time DESC, ple.id DESC
        LIMIT ? OFFSET ?
        """,
        (*args, size, (page - 1) * size)
    ).fetchall()
    items = []
    for r in rows:
        d = dict(r)
        d['raw_metadata'] = obj(d['raw_metadata'])
        items.append(d)

    sources = {
        r['source_channel']: r['n']
        for r in c.execute(
            f"SELECT source_channel, COUNT(*) n FROM process_lifecycle_events ple WHERE {where_sql} GROUP BY source_channel",
            args
        ).fetchall()
    }
    return {
        'period': {'start': start, 'end': end},
        'sources': sources,
        'items': items,
        'total': total,
        'page': page,
        'page_size': size,
    }

def process_detail(c, instance_key: str):
    r = c.execute(
        "SELECT pi.*, d.hostname FROM process_instances pi LEFT JOIN devices d ON d.id=pi.device_id WHERE pi.instance_key=?",
        (instance_key,)
    ).fetchone()
    if not r:
        raise HTTPException(404, 'Process instance not found')
    proc = dict(r)
    proc['source_event_ids'] = obj(proc['source_event_ids'])
    proc['raw_metadata'] = obj(proc['raw_metadata'])

    samples = [
        dict(s) for s in c.execute(
            'SELECT * FROM process_samples WHERE instance_key=? ORDER BY sampled_at DESC LIMIT 60',
            (instance_key,)
        ).fetchall()
    ]
    samples.reverse()
    proc['samples'] = samples
    proc['latest_sample'] = samples[-1] if samples else None
    proc['cpu_display'] = (
        f"{proc['latest_sample']['cpu_percent']:.1f}%"
        if proc['latest_sample'] and proc['latest_sample'].get('cpu_percent') is not None
        else 'Unavailable (first sample)'
    )

    # Verified lineage chain (ancestors up to 6 levels, only via verified parent_instance_key)
    ancestors = []
    curr_parent_key = proc.get('parent_instance_key')
    seen_keys = {instance_key}
    while curr_parent_key and curr_parent_key not in seen_keys and len(ancestors) < 6:
        seen_keys.add(curr_parent_key)
        p_row = c.execute(
            'SELECT instance_key, pid, process_guid, name, executable_path, command_line, command_line_state, '
            'account, user_sid, creation_time, first_seen_at, last_seen_at, exited_at, observed_state, '
            'parent_instance_key, parent_pid, parent_confidence, identity_confidence, signature_state '
            'FROM process_instances WHERE instance_key=?',
            (curr_parent_key,)
        ).fetchone()
        if not p_row:
            break
        p_dict = dict(p_row)
        ancestors.append(p_dict)
        curr_parent_key = p_dict.get('parent_instance_key')
    ancestors.reverse()
    proc['ancestors'] = ancestors

    # Verified children
    children = [
        dict(ch) for ch in c.execute(
            'SELECT instance_key, pid, process_guid, name, executable_path, command_line, command_line_state, '
            'account, user_sid, creation_time, first_seen_at, last_seen_at, exited_at, observed_state, '
            'parent_pid, parent_confidence, identity_confidence, signature_state '
            'FROM process_instances WHERE parent_instance_key=? ORDER BY COALESCE(creation_time,first_seen_at) ASC LIMIT 100',
            (instance_key,)
        ).fetchall()
    ]
    proc['children'] = children

    # Lifecycle events
    proc['lifecycle_events'] = [
        {**dict(le), 'raw_metadata': obj(le['raw_metadata'])}
        for le in c.execute(
            'SELECT * FROM process_lifecycle_events WHERE instance_key=? ORDER BY event_time ASC',
            (instance_key,)
        ).fetchall()
    ]

    # Correlation links
    corr_rows = c.execute(
        "SELECT * FROM correlation_links WHERE (source_type='process_instance' AND source_id=?) "
        "OR (target_type='process_instance' AND target_id=?) ORDER BY event_time DESC",
        (instance_key, instance_key)
    ).fetchall()
    proc['correlations'] = [_decode_correlation_link(c, cr) for cr in corr_rows]
    return proc

def process_tree(c, params):
    instance_key = params.get('instance_key')
    if instance_key:
        detail = process_detail(c, instance_key)
        return {
            'focus_instance_key': instance_key,
            'ancestors': detail['ancestors'],
            'process': detail,
            'children': detail['children'],
            'lineage_note': (
                detail['parent_confidence']
                if detail.get('parent_instance_key')
                else f"Parent not verified ({detail.get('parent_confidence') or 'PID alone is not sufficient to prove lineage without creation-time/ProcessGuid validation'})."
            )
        }
    # Device-level verified lineage roots
    device_id = params.get('device_id')
    where = "WHERE device_id=?" if device_id else ""
    args = (device_id,) if device_id else ()
    rows = [
        dict(r) for r in c.execute(
            f"SELECT instance_key, device_id, pid, name, executable_path, command_line, account, creation_time, "
            f"first_seen_at, last_seen_at, observed_state, parent_instance_key, parent_pid, parent_confidence, signature_state "
            f"FROM process_instances {where} ORDER BY last_seen_at DESC LIMIT 200",
            args
        ).fetchall()
    ]
    by_key = {r['instance_key']: {**r, 'children': []} for r in rows}
    roots = []
    for r in by_key.values():
        pkey = r.get('parent_instance_key')
        if pkey and pkey in by_key:
            by_key[pkey]['children'].append(r)
        else:
            roots.append(r)
    return {'roots': roots, 'total_nodes': len(rows)}

def _decode_review(rv) -> dict:
    d = dict(rv)
    d['state'] = d.get('decision') or d.get('state') or 'Unreviewed'
    d['reviewer'] = d.get('actor') or d.get('reviewer')
    d['notes'] = d.get('note') or d.get('notes')
    d['updated_at'] = d.get('created_at') or d.get('updated_at')
    return d

def _decode_correlation_link(c, r) -> dict:
    d = dict(r)
    d['matched_fields'] = obj(d['matched_fields'])
    d['missing_fields'] = obj(d['missing_fields'])
    d['competing_candidates'] = obj(d['competing_candidates'])
    rev = c.execute(
        'SELECT * FROM correlation_reviews WHERE case_key=? ORDER BY created_at DESC LIMIT 1',
        (d['case_key'],)
    ).fetchone()
    d['review'] = _decode_review(rev) if rev else {'state': 'Unreviewed', 'reviewer': None, 'notes': None, 'updated_at': None}
    return d

def browser_overview(c, params):
    start, end = period(params, default_hours=int(params.get('hours', 24)))
    device_id = params.get('device_id')
    user_sid = params.get('user_sid')
    profile_id = params.get('profile_id')
    search = (params.get('q') or '').strip()

    # Enrolled profiles
    prof_q = "SELECT bp.*, d.hostname FROM browser_profiles bp LEFT JOIN devices d ON d.id=bp.device_id WHERE 1=1"
    prof_args = []
    if device_id:
        prof_q += " AND bp.device_id=?"
        prof_args.append(device_id)
    if user_sid:
        prof_q += " AND bp.user_sid=?"
        prof_args.append(user_sid)
    if profile_id:
        prof_q += " AND bp.profile_id=?"
        prof_args.append(profile_id)
    prof_q += " ORDER BY bp.last_seen_at DESC"
    profiles = []
    for r in c.execute(prof_q, prof_args).fetchall():
        p = dict(r)
        p['diagnostics'] = obj(p['diagnostics'])
        p['freshness'] = presence(p['last_seen_at'])
        profiles.append(p)

    # Collection gaps
    gap_q = "SELECT g.*, bp.browser_name, bp.profile_label, d.hostname FROM browser_collection_gaps g LEFT JOIN browser_profiles bp ON bp.profile_id=g.profile_id LEFT JOIN devices d ON d.id=g.device_id WHERE g.started_at>=? AND g.started_at<=?"
    gap_args = [start, end]
    if device_id:
        gap_q += " AND g.device_id=?"
        gap_args.append(device_id)
    if user_sid:
        gap_q += " AND g.user_sid=?"
        gap_args.append(user_sid)
    gap_q += " ORDER BY g.started_at DESC LIMIT 50"
    gaps = [{**dict(g), 'details': obj(g['details'])} for g in c.execute(gap_q, gap_args).fetchall()]

    # Navigations filter
    nav_clauses = ['bn.navigation_time>=?', 'bn.navigation_time<=?']
    nav_args = [start, end]
    if device_id:
        nav_clauses.append('bn.device_id=?')
        nav_args.append(device_id)
    if user_sid:
        nav_clauses.append('bn.user_sid=?')
        nav_args.append(user_sid)
    if profile_id:
        nav_clauses.append('bn.profile_id=?')
        nav_args.append(profile_id)
    if search:
        pat = f"%{search[:200]}%"
        nav_clauses.append("(bn.normalized_domain LIKE ? OR COALESCE(bn.account,'') LIKE ? OR COALESCE(bn.visit_kind,'') LIKE ?)")
        nav_args.extend([pat] * 3)
    nav_where = ' AND '.join(nav_clauses)

    # Downloads filter
    dl_clauses = ['bd.started_at>=?', 'bd.started_at<=?']
    dl_args = [start, end]
    if device_id:
        dl_clauses.append('bd.device_id=?')
        dl_args.append(device_id)
    if user_sid:
        dl_clauses.append('bd.user_sid=?')
        dl_args.append(user_sid)
    if profile_id:
        dl_clauses.append('bd.profile_id=?')
        dl_args.append(profile_id)
    if search:
        pat = f"%{search[:200]}%"
        dl_clauses.append("(COALESCE(bd.filename,'') LIKE ? OR COALESCE(bd.source_domain,'') LIKE ? OR COALESCE(bd.final_path,'') LIKE ? OR COALESCE(bd.account,'') LIKE ?)")
        dl_args.extend([pat] * 4)
    dl_where = ' AND '.join(dl_clauses)

    unique_domains = c.execute(f"SELECT COUNT(DISTINCT bn.normalized_domain) FROM browser_navigations bn WHERE {nav_where}", nav_args).fetchone()[0]
    top_level_visits = c.execute(f"SELECT COUNT(*) FROM browser_navigations bn WHERE {nav_where}", nav_args).fetchone()[0]
    completed_downloads = c.execute(f"SELECT COUNT(*) FROM browser_downloads bd WHERE {dl_where} AND bd.state='completed'", dl_args).fetchone()[0]
    other_downloads = c.execute(f"SELECT COUNT(*) FROM browser_downloads bd WHERE {dl_where} AND bd.state!='completed'", dl_args).fetchone()[0]
    completed_bytes = c.execute(f"SELECT COALESCE(SUM(bd.final_size_bytes),0) FROM browser_downloads bd WHERE {dl_where} AND bd.state='completed'", dl_args).fetchone()[0]
    downloads_with_followup = c.execute(
        f"SELECT COUNT(DISTINCT bd.id) FROM browser_downloads bd WHERE {dl_where} AND EXISTS ("
        f"SELECT 1 FROM correlation_links cl WHERE cl.source_type='browser_download' AND cl.source_id=bd.id)",
        dl_args
    ).fetchone()[0]

    # Domain breakdown
    policy_domains = [str(d).strip().casefold() for d in (settings(c).get('restricted_domains') or []) if str(d).strip()]
    dom_rows = c.execute(
        f"""
        SELECT bn.normalized_domain,
               MAX(bn.scheme) AS scheme,
               COUNT(*) AS visit_count,
               MIN(bn.navigation_time) AS first_seen,
               MAX(bn.navigation_time) AS last_seen,
               COUNT(DISTINCT bn.profile_id) AS profiles_count,
               GROUP_CONCAT(DISTINCT bn.account) AS accounts,
               GROUP_CONCAT(DISTINCT d.hostname) AS devices,
               GROUP_CONCAT(DISTINCT bn.visit_kind) AS visit_kinds,
               GROUP_CONCAT(DISTINCT bp.browser_name) AS browsers,
               (SELECT COUNT(*) FROM browser_downloads bd2 WHERE (bd2.source_domain=bn.normalized_domain OR bd2.referrer_domain=bn.normalized_domain) AND bd2.started_at>=? AND bd2.started_at<=?) AS downloads_from_domain,
               (SELECT cl.case_key FROM correlation_links cl WHERE cl.source_type='browser_navigation' AND cl.source_id IN (SELECT bn2.id FROM browser_navigations bn2 WHERE bn2.normalized_domain=bn.normalized_domain) ORDER BY cl.event_time DESC LIMIT 1) AS correlated_case_key
        FROM browser_navigations bn
        LEFT JOIN devices d ON d.id = bn.device_id
        LEFT JOIN browser_profiles bp ON bp.profile_id = bn.profile_id
        WHERE {nav_where}
        GROUP BY bn.normalized_domain
        ORDER BY last_seen DESC
        LIMIT 100
        """,
        (start, end, *nav_args)
    ).fetchall()

    domain_breakdown = []
    for r in dom_rows:
        item = dict(r)
        dom = item['normalized_domain']
        item['policy_match'] = any(dom == pd or dom.endswith('.' + pd) for pd in policy_domains)
        domain_breakdown.append(item)

    return {
        'period': {'start': start, 'end': end},
        'profiles': profiles,
        'gaps': gaps,
        'summary': {
            'unique_domains': unique_domains,
            'top_level_visits': top_level_visits,
            'completed_downloads': completed_downloads,
            'in_progress_or_interrupted_downloads': other_downloads,
            'completed_download_bytes': completed_bytes,
            'downloads_with_followup': downloads_with_followup,
            'enrolled_profiles': len(profiles),
        },
        'domain_breakdown': domain_breakdown,
        'privacy_scope': {
            'collected': [
                'Normalized HTTP/HTTPS hostname/domain and scheme for top-level frame (frameId=0) navigations',
                'Navigation transition type, qualifiers, and tab reload/redirect classification',
                'Download filename, extension, MIME type, target path, state revisions, final byte size, and source/referrer domain',
                'Completed-file SHA-256 hash when verified in the local Downloads directory by the native host',
                'Enrolled browser profile ID and OS-verified Windows user SID from the local native messaging host'
            ],
            'excluded': [
                'Full URL paths, query strings, URL parameters, and fragments (#hash)',
                'Page titles, DOM contents, keystrokes, form inputs, cookies, and credentials',
                'Incognito / InPrivate browsing windows and non-enrolled personal browser profiles',
                'Subframe / iframe background ad or tracker requests (frameId != 0)',
                'Pre-enrollment historical browser SQLite databases'
            ]
        }
    }

def browser_navigations_list(c, params):
    start, end = period(params, default_hours=int(params.get('hours', 24)))
    page, size = pagination(params)
    clauses = ['bn.navigation_time>=?', 'bn.navigation_time<=?']
    args = [start, end]
    for key in ('device_id', 'user_sid', 'profile_id', 'normalized_domain'):
        if params.get(key):
            clauses.append(f'bn.{key}=?')
            args.append(params[key])
    if params.get('domain'):
        clauses.append('bn.normalized_domain=?')
        args.append(params['domain'].strip().casefold())
    if params.get('q'):
        pat = f"%{params['q'][:200]}%"
        clauses.append("(bn.normalized_domain LIKE ? OR COALESCE(bn.account,'') LIKE ? OR COALESCE(bn.visit_kind,'') LIKE ?)")
        args.extend([pat] * 3)
    where_sql = ' AND '.join(clauses)
    total = c.execute(f"SELECT COUNT(*) FROM browser_navigations bn WHERE {where_sql}", args).fetchone()[0]
    rows = c.execute(
        f"""
        SELECT bn.*, d.hostname, bp.browser_name, bp.profile_label,
               (SELECT cl.case_key FROM correlation_links cl WHERE cl.source_type='browser_navigation' AND cl.source_id=bn.id LIMIT 1) AS correlated_case_key
        FROM browser_navigations bn
        LEFT JOIN devices d ON d.id = bn.device_id
        LEFT JOIN browser_profiles bp ON bp.profile_id = bn.profile_id
        WHERE {where_sql}
        ORDER BY bn.navigation_time DESC, bn.id DESC
        LIMIT ? OFFSET ?
        """,
        (*args, size, (page - 1) * size)
    ).fetchall()
    items = []
    for r in rows:
        item = dict(r)
        item['transition_qualifiers'] = obj(item['transition_qualifiers'])
        item['raw_sanitized_evidence'] = obj(item['raw_sanitized_evidence'])
        items.append(item)
    return {'items': items, 'total': total, 'page': page, 'page_size': size}

def _fetch_download_revisions(c, download_id: str) -> list[dict]:
    revs = []
    for idx, rev in enumerate(
        c.execute(
            'SELECT * FROM browser_download_revisions WHERE download_id=? ORDER BY observed_at ASC, received_at ASC',
            (download_id,)
        ).fetchall(),
        start=1
    ):
        rd = dict(rev)
        rd['revision_no'] = idx
        rd['details'] = obj(rd.get('details'))
        rd['raw_sanitized_evidence'] = rd['details']
        revs.append(rd)
    return revs

def browser_downloads_list(c, params):
    start, end = period(params, default_hours=int(params.get('hours', 24)))
    page, size = pagination(params)
    clauses = ['bd.started_at>=?', 'bd.started_at<=?']
    args = [start, end]
    for key in ('device_id', 'user_sid', 'profile_id', 'state'):
        if params.get(key):
            clauses.append(f'bd.{key}=?')
            args.append(params[key])
    if params.get('q'):
        pat = f"%{params['q'][:200]}%"
        clauses.append("(COALESCE(bd.filename,'') LIKE ? OR COALESCE(bd.source_domain,'') LIKE ? OR COALESCE(bd.final_path,'') LIKE ? OR COALESCE(bd.account,'') LIKE ?)")
        args.extend([pat] * 4)
    where_sql = ' AND '.join(clauses)
    total = c.execute(f"SELECT COUNT(*) FROM browser_downloads bd WHERE {where_sql}", args).fetchone()[0]
    completed_bytes = c.execute(f"SELECT COALESCE(SUM(bd.final_size_bytes),0) FROM browser_downloads bd WHERE {where_sql} AND bd.state='completed'", args).fetchone()[0]
    rows = c.execute(
        f"""
        SELECT bd.*, d.hostname, bp.profile_label,
               (SELECT COUNT(*) FROM browser_download_revisions bdr WHERE bdr.download_id=bd.id) AS revision_count
        FROM browser_downloads bd
        LEFT JOIN devices d ON d.id = bd.device_id
        LEFT JOIN browser_profiles bp ON bp.profile_id = bd.profile_id
        WHERE {where_sql}
        ORDER BY COALESCE(bd.completed_at, bd.started_at) DESC, bd.id DESC
        LIMIT ? OFFSET ?
        """,
        (*args, size, (page - 1) * size)
    ).fetchall()

    items = []
    for r in rows:
        dl = dict(r)
        dl['raw_sanitized_evidence'] = obj(dl['raw_sanitized_evidence'])
        dl['revisions'] = _fetch_download_revisions(c, dl['id'])
        corr_rows = c.execute(
            "SELECT * FROM correlation_links WHERE (source_type='browser_download' AND source_id=?) "
            "OR (target_type='browser_download' AND target_id=?) ORDER BY event_time ASC",
            (dl['id'], dl['id'])
        ).fetchall()
        corrs = [_decode_correlation_link(c, cr) for cr in corr_rows]
        # Enrich process follow-up summary if present
        followup_procs = []
        for cr in corrs:
            if cr['source_type'] == 'browser_download' and cr['target_type'] == 'process_instance':
                p_row = c.execute('SELECT instance_key, pid, name, executable_path, command_line, creation_time FROM process_instances WHERE instance_key=?', (cr['target_id'],)).fetchone()
                if p_row:
                    followup_procs.append({**dict(p_row), 'confidence': cr['confidence'], 'relationship_label': cr['relationship_label'], 'time_delta_seconds': cr['time_delta_seconds'], 'case_key': cr['case_key']})
        dl['correlations'] = corrs
        dl['followup_processes'] = followup_procs
        dl['case_key'] = corrs[0]['case_key'] if corrs else None
        items.append(dl)
    return {
        'items': items,
        'total': total,
        'page': page,
        'page_size': size,
        'summary': {'completed_download_bytes': completed_bytes, 'total_downloads': total},
    }

def browser_download_detail(c, download_id: str):
    r = c.execute(
        "SELECT bd.*, d.hostname, bp.profile_label FROM browser_downloads bd "
        "LEFT JOIN devices d ON d.id=bd.device_id LEFT JOIN browser_profiles bp ON bp.profile_id=bd.profile_id "
        "WHERE bd.id=?",
        (download_id,)
    ).fetchone()
    if not r:
        raise HTTPException(404, 'Browser download record not found')
    dl = dict(r)
    dl['raw_sanitized_evidence'] = obj(dl['raw_sanitized_evidence'])
    dl['revisions'] = _fetch_download_revisions(c, download_id)
    corr_rows = c.execute(
        "SELECT * FROM correlation_links WHERE (source_type='browser_download' AND source_id=?) "
        "OR (target_type='browser_download' AND target_id=?) ORDER BY event_time ASC",
        (download_id, download_id)
    ).fetchall()
    dl['correlations'] = [_decode_correlation_link(c, cr) for cr in corr_rows]
    return dl

def _build_timeline_chain(c, case_key: str) -> dict:
    link_rows = c.execute(
        'SELECT * FROM correlation_links WHERE case_key=? ORDER BY event_time ASC, id ASC',
        (case_key,)
    ).fetchall()
    if not link_rows:
        raise HTTPException(404, 'Investigation timeline case not found')
    links = [_decode_correlation_link(c, lr) for lr in link_rows]

    nav_ids = set()
    dl_ids = set()
    proc_keys = set()
    for l in links:
        for stype, sid in ((l['source_type'], l['source_id']), (l['target_type'], l['target_id'])):
            if stype == 'browser_navigation':
                nav_ids.add(sid)
            elif stype == 'browser_download':
                dl_ids.add(sid)
            elif stype == 'process_instance':
                proc_keys.add(sid)

    steps = []
    navigations = []
    for nid in nav_ids:
        nr = c.execute(
            "SELECT bn.*, d.hostname, bp.browser_name, bp.profile_label FROM browser_navigations bn "
            "LEFT JOIN devices d ON d.id=bn.device_id LEFT JOIN browser_profiles bp ON bp.profile_id=bn.profile_id "
            "WHERE bn.id=?",
            (nid,)
        ).fetchone()
        if nr:
            nd = dict(nr)
            nd['transition_qualifiers'] = obj(nd['transition_qualifiers'])
            nd['raw_sanitized_evidence'] = obj(nd['raw_sanitized_evidence'])
            navigations.append(nd)
            steps.append({
                'step_type': 'browser_navigation',
                'id': nd['id'],
                'time': nd['navigation_time'],
                'received_at': nd['received_at'],
                'title': f"Navigated to {nd['normalized_domain']}",
                'subtitle': f"{nd.get('browser_name') or 'Browser'} ({nd.get('profile_label') or nd['profile_id'][:8]}) • {nd['visit_kind']} ({nd['transition_type']})",
                'source_sensor': 'Enrolled Browser MV3 Extension + Native Host',
                'device_id': nd['device_id'],
                'hostname': nd.get('hostname'),
                'user_sid': nd['user_sid'],
                'account': nd['account'],
                'data': nd,
            })

    downloads = []
    for did in dl_ids:
        dr = c.execute(
            "SELECT bd.*, d.hostname, bp.profile_label FROM browser_downloads bd "
            "LEFT JOIN devices d ON d.id=bd.device_id LEFT JOIN browser_profiles bp ON bp.profile_id=bd.profile_id "
            "WHERE bd.id=?",
            (did,)
        ).fetchone()
        if dr:
            dd = dict(dr)
            dd['raw_sanitized_evidence'] = obj(dd['raw_sanitized_evidence'])
            dd['revisions'] = _fetch_download_revisions(c, did)
            downloads.append(dd)
            steps.append({
                'step_type': 'browser_download',
                'id': dd['id'],
                'time': dd.get('completed_at') or dd['started_at'],
                'received_at': dd['received_at'],
                'title': f"Download {dd['state']}: {dd.get('filename') or 'unknown'}",
                'subtitle': f"Source: {dd.get('source_domain') or 'Unavailable'} → {dd.get('final_path') or 'path unknown'} ({dd.get('final_size_bytes') or 0} bytes)",
                'source_sensor': 'Browser Downloads API + Native Host File Verifier',
                'device_id': dd['device_id'],
                'hostname': dd.get('hostname'),
                'user_sid': dd['user_sid'],
                'account': dd['account'],
                'data': dd,
            })

    processes = []
    for pkey in proc_keys:
        pr = c.execute(
            "SELECT pi.*, d.hostname FROM process_instances pi LEFT JOIN devices d ON d.id=pi.device_id WHERE pi.instance_key=?",
            (pkey,)
        ).fetchone()
        if pr:
            pd = dict(pr)
            pd['source_event_ids'] = obj(pd['source_event_ids'])
            pd['raw_metadata'] = obj(pd['raw_metadata'])
            pd['samples'] = [dict(s) for s in c.execute('SELECT * FROM process_samples WHERE instance_key=? ORDER BY sampled_at ASC LIMIT 30', (pkey,)).fetchall()]
            pd['lifecycle_events'] = [dict(le) for le in c.execute('SELECT * FROM process_lifecycle_events WHERE instance_key=? ORDER BY event_time ASC', (pkey,)).fetchall()]
            processes.append(pd)
            ptime = pd.get('creation_time') or pd['first_seen_at']
            steps.append({
                'step_type': 'process_instance',
                'id': pd['instance_key'],
                'time': ptime,
                'received_at': pd['last_seen_at'],
                'title': f"Process observed: {pd['name']} (PID {pd['pid']})",
                'subtitle': pd.get('command_line') or pd.get('executable_path') or f"Command line: {pd.get('command_line_state')}",
                'source_sensor': f"Endpoint Process Collector ({pd['source_kind']})",
                'device_id': pd['device_id'],
                'hostname': pd.get('hostname'),
                'user_sid': pd.get('user_sid'),
                'account': pd.get('account'),
                'data': pd,
            })

    steps.sort(key=lambda s: s['time'] or '')

    # Determine highest confidence & primary summary (preferring download->process links when present)
    conf_rank = {'High': 3, 'Medium': 2, 'Low': 1}
    dl_proc_links = [l for l in links if l['link_kind'].startswith('download_to_')]
    primary_pool = dl_proc_links if dl_proc_links else links
    top_link = max(primary_pool, key=lambda l: conf_rank.get(l['confidence'], 0))
    first_time = min((s['time'] for s in steps if s.get('time')), default=links[0]['event_time'])
    last_time = max((s['time'] for s in steps if s.get('time')), default=links[-1]['event_time'])

    device_id = top_link['device_id']
    user_sid = top_link.get('user_sid')
    account = top_link.get('account')
    dev_row = c.execute('SELECT hostname FROM devices WHERE id=?', (device_id,)).fetchone()
    hostname = dev_row['hostname'] if dev_row else device_id

    # Collection gaps overlapping window (+/- 15 minutes)
    gap_start = stamp(dt(first_time) - timedelta(minutes=15))
    gap_end = stamp(dt(last_time) + timedelta(minutes=15))
    gaps = [
        {**dict(g), 'details': obj(g['details'])}
        for g in c.execute(
            'SELECT * FROM browser_collection_gaps WHERE device_id=? AND started_at<=? AND COALESCE(ended_at,?)>=? ORDER BY started_at ASC',
            (device_id, gap_end, now(), gap_start)
        ).fetchall()
    ]

    # Reviews
    reviews = [
        _decode_review(rv) for rv in c.execute(
            'SELECT * FROM correlation_reviews WHERE case_key=? ORDER BY created_at DESC',
            (case_key,)
        ).fetchall()
    ]
    latest_review = reviews[0] if reviews else {'state': 'Unreviewed', 'reviewer': None, 'notes': None, 'updated_at': None}

    # Related alerts in window for same user/device
    related_alerts = [
        decode_alert(ar) for ar in c.execute(
            'SELECT * FROM alerts WHERE device_id=? AND last_time>=? AND first_time<=? ORDER BY last_time DESC LIMIT 10',
            (device_id, gap_start, gap_end)
        ).fetchall()
    ]

    # Build human-readable chain title
    dl_name = downloads[0].get('filename') if downloads else None
    dom_name = navigations[0].get('normalized_domain') if navigations else (downloads[0].get('source_domain') if downloads else None)
    proc_names = [p['name'] for p in processes]
    if dom_name and dl_name and proc_names:
        chain_title = f"{dom_name} → {dl_name} → {' / '.join(proc_names[:2])}"
    elif dl_name and proc_names:
        chain_title = f"Download {dl_name} → {' / '.join(proc_names[:2])}"
    elif dom_name and dl_name:
        chain_title = f"Navigation {dom_name} → Download {dl_name}"
    else:
        chain_title = top_link['relationship_label']

    return {
        'case_key': case_key,
        'title': chain_title,
        'confidence': top_link['confidence'],
        'highest_confidence': top_link['confidence'],
        'primary_relationship': top_link['relationship_label'],
        'device_id': device_id,
        'hostname': hostname,
        'user_sid': user_sid,
        'account': account,
        'first_time': first_time,
        'last_time': last_time,
        'review': latest_review,
        'review_status': latest_review['state'],
        'reviews': reviews,
        'review_notes': reviews,
        'steps': steps,
        'links': links,
        'navigations': navigations,
        'downloads': downloads,
        'download': downloads[0] if downloads else None,
        'processes': processes,
        'collection_gaps': gaps,
        'related_alerts': related_alerts,
    }

def timeline_list(c, params):
    start, end = period(params, default_hours=int(params.get('hours', 720)))
    device_id = params.get('device_id')
    user_sid = params.get('user_sid')
    conf_filter = params.get('confidence')
    review_filter = params.get('review_state')
    search = (params.get('q') or '').strip().casefold()

    clauses = ['cl.event_time>=?', 'cl.event_time<=?']
    args = [start, end]
    if device_id:
        clauses.append('cl.device_id=?')
        args.append(device_id)
    if user_sid:
        clauses.append('cl.user_sid=?')
        args.append(user_sid)
    where_sql = ' AND '.join(clauses)

    case_keys = [
        r['case_key'] for r in c.execute(
            f"SELECT case_key, MAX(event_time) AS latest_time FROM correlation_links cl WHERE {where_sql} GROUP BY case_key ORDER BY latest_time DESC LIMIT 100",
            args
        ).fetchall()
    ]

    chains = []
    for ck in case_keys:
        chain = _build_timeline_chain(c, ck)
        if conf_filter and chain['confidence'].casefold() != conf_filter.casefold():
            continue
        if review_filter and chain['review']['state'].casefold() != review_filter.casefold():
            continue
        if search:
            hay = js([chain['title'], chain.get('account'), chain.get('hostname'), chain['primary_relationship']]).casefold()
            if search not in hay:
                continue
        chains.append(chain)

    summary = {
        'total_chains': len(chains),
        'total_cases': len(chains),
        'high_confidence': sum(1 for ch in chains if ch['confidence'] == 'High'),
        'medium_confidence': sum(1 for ch in chains if ch['confidence'] == 'Medium'),
        'low_confidence': sum(1 for ch in chains if ch['confidence'] == 'Low'),
        'unreviewed': sum(1 for ch in chains if ch['review']['state'] == 'Unreviewed'),
        'needs_followup': sum(1 for ch in chains if ch['review']['state'] == 'Needs follow-up'),
        'confirmed_violation': sum(1 for ch in chains if ch['review']['state'] == 'Confirmed policy violation'),
        'benign_expected': sum(1 for ch in chains if ch['review']['state'] == 'Benign / expected activity'),
    }
    return {
        'period': {'start': start, 'end': end},
        'summary': summary,
        'items': chains,
        'cases': chains,
        'total': len(chains),
    }

