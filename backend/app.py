from __future__ import annotations
import csv, io, json, logging, os, secrets, shutil, sqlite3
from contextlib import asynccontextmanager
from datetime import timedelta
from logging.handlers import RotatingFileHandler
from pathlib import Path
from fastapi import FastAPI, Request, HTTPException, Response
from fastapi.responses import FileResponse, JSONResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from .db import Database, now, dt, stamp, ago, uid, digest, js, obj, row, audit, settings, presence
from .security import current, require, login, create_user
from .schemas import Login, NewUser, UserUpdate, Enroll, Batch, CollectorStatus, CaseUpdate, Note, CorrelationReviewInput, RuleUpdate, AppSettings, PrimaryDevice, Job
from .rules import seed_rules, readiness, evaluate
from .ingestion import Worker, find_device, ALLOWED_KINDS_BY_COLLECTOR
from . import queries as q

ROOT=Path(__file__).resolve().parent.parent

class Boundaries:
    def __init__(self,app,testing=False): self.app=app; self.testing=testing
    async def __call__(self,scope,receive,send):
        if scope['type']!='http': return await self.app(scope,receive,send)
        headers={k.decode().lower():v.decode() for k,v in scope['headers']}
        host=headers.get('host','').split(':')[0].lower()
        allowed=[h.strip().lower() for h in os.environ.get('ADMONITOR_HOSTS','localhost,127.0.0.1,0.0.0.0,::1,192.168.77.1,desktop-iaut7r9,testserver').split(',') if h.strip()]
        if self.testing and 'testserver' not in allowed: allowed.append('testserver')
        if host and host not in allowed:
            return await JSONResponse({'detail':'Host not allowed. Configure ADMONITOR_HOSTS explicitly.'},400)(scope,receive,send)
        lab_http=os.environ.get('ADMONITOR_ALLOW_LAB_HTTP','1')=='1'  # isolated firewalled lab link
        if not self.testing and not lab_http and scope['scheme']!='https' and host not in ('127.0.0.1','localhost','0.0.0.0','::1'):
            return await JSONResponse({'detail':'Cross-machine traffic requires TLS'},400)(scope,receive,send)
        origin=headers.get('origin')
        if origin and origin!=scope['scheme']+'://'+headers.get('host',''):
            return await JSONResponse({'detail':'Cross-origin requests are not accepted'},403)(scope,receive,send)
        limit=2*1024*1024; consumed=0; messages=[]
        while True:
            message=await receive()
            if message['type']=='http.disconnect': return
            consumed+=len(message.get('body',b''))
            if consumed>limit: return await JSONResponse({'detail':'Request exceeds 2 MiB'},413)(scope,receive,send)
            messages.append(message)
            if not message.get('more_body'): break
        async def bounded_receive():
            if messages: return messages.pop(0)
            return await receive()
        async def secure_send(message):
            if message['type']=='http.response.start':
                message['headers']+= [(b'x-content-type-options',b'nosniff'),(b'x-frame-options',b'DENY'),(b'referrer-policy',b'no-referrer'),
                    (b'content-security-policy',b"default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"),
                    (b'cache-control',b'no-store')]
            await send(message)
        await self.app(scope,bounded_receive,secure_send)

def make_app(db_path=None,testing=False,start_worker=True):
    db=Database(db_path or os.environ.get('ADMONITOR_DB',str(ROOT/'data'/'admonitor.db'))); db.migrate()
    with db.tx() as c: seed_rules(c)
    worker=Worker(db)
    @asynccontextmanager
    async def lifespan(app):
        if start_worker:
            try: worker.start()
            except RuntimeError: pass
        yield
        if start_worker: worker.close()
    app=FastAPI(title='AD Monitor',version='2.0.0',docs_url=None,redoc_url=None,openapi_url=None,lifespan=lifespan)
    app.state.db=db; app.state.worker=worker; app.add_middleware(Boundaries,testing=testing)
    logger=logging.getLogger('admonitor')
    if not testing and not logger.handlers:
        logdir=db.path.parent/'logs'; logdir.mkdir(exist_ok=True)
        handler=RotatingFileHandler(logdir/'application.log',maxBytes=1_000_000,backupCount=3,encoding='utf8')
        handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s')); logger.addHandler(handler); logger.setLevel(logging.INFO)

    @app.exception_handler(sqlite3.IntegrityError)
    async def integrity(request,exc): return JSONResponse({'detail':'The change conflicts with an existing record or reference'},409)
    @app.exception_handler(ValueError)
    async def invalid(request,exc): return JSONResponse({'detail':str(exc)[:500]},422)

    @app.get('/api/auth/status')
    def auth_status():
        with db.read() as c: return {'initialized':bool(c.execute('SELECT 1 FROM users LIMIT 1').fetchone())}
    @app.post('/api/auth/setup')
    def auth_setup(body:Login):
        with db.tx() as c:
            if c.execute('SELECT 1 FROM users LIMIT 1').fetchone():
                raise HTTPException(400,'System already initialized with an administrator account')
            ident=create_user(c,body.username.strip(),body.password,'Admin','initial-setup')
        return {'ok':True,'id':ident}
    @app.post('/api/auth/login')
    def sign_in(body:Login,request:Request,response:Response):
        client_host=request.client.host if request.client else '127.0.0.1'
        result=login(db,body.username,body.password,client_host)
        response.set_cookie('admonitor_session',result['token'],httponly=True,secure=request.url.scheme=='https',samesite='lax',max_age=28800,path='/')
        return result
    @app.get('/api/auth/me')
    def me(request:Request): return current(request)
    @app.post('/api/auth/logout')
    def logout(request:Request,response:Response):
        user=current(request)
        auth=request.headers.get('authorization','')
        token=request.cookies.get('admonitor_session','') or (auth[7:].strip() if auth.startswith('Bearer ') else '')
        with db.tx() as c:
            c.execute('DELETE FROM sessions WHERE token_hash=?',(digest(token),)); audit(c,user['username'],'logout',{})
        response.delete_cookie('admonitor_session'); return {'ok':True}
    @app.get('/api/openapi.json')
    def api_docs(request:Request): current(request); return app.openapi()
    @app.get('/api/overview')
    def overview(request:Request):
        current(request)
        with db.read() as c: return q.overview(c,request.query_params)
    @app.get('/api/events')
    def events(request:Request):
        current(request)
        with db.read() as c: return q.events(c,request.query_params)
    @app.get('/api/export/events')
    @app.get('/api/events/export')
    def export_events(request:Request,format:str='csv'):
        user=current(request)
        if format not in ('csv','json'): raise HTTPException(422,'Use csv or json')
        with db.read() as c: data=q.events(c,request.query_params,export=True); zone=settings(c)['timezone']
        meta={'generated_at':now(),'timezone':zone,'stored_times':'UTC','filters':dict(request.query_params),'total':data['total'],'exported':len(data['items']),'truncated':data['truncated'],'provenance':'Persisted source evidence; missing telemetry is not evidence of no activity'}
        with db.tx() as c: audit(c,user['username'],'events_export',meta)
        if format=='json': return Response(js({'metadata':meta,'events':data['items']}),media_type='application/json',headers={'Content-Disposition':'attachment; filename="ad-monitor-events.json"'})
        output=io.StringIO(newline=''); fields=list(data['items'][0]) if data['items'] else q.EVENT_LIST.replace('e.','').split(',')
        fields+=['export_timezone','export_generated_at','export_truncated']
        writer=csv.DictWriter(output,fieldnames=fields); writer.writeheader()
        def safe(value):
            if isinstance(value,str) and value.lstrip().startswith(('=','+','-','@','\t','\r')): return "'"+value
            return value
        for r in data['items']: writer.writerow({k:safe(v) for k,v in {**r,'export_timezone':zone,'export_generated_at':meta['generated_at'],'export_truncated':data['truncated']}.items()})
        return Response('\ufeff'+output.getvalue(),media_type='text/csv',headers={'Content-Disposition':'attachment; filename="ad-monitor-events.csv"','X-Export-Truncated':str(data['truncated']).lower()})
    @app.get('/api/events/{ident}')
    def event_detail(ident:str,request:Request):
        current(request)
        with db.read() as c:
            e=row(c.execute('SELECT * FROM events WHERE id=?',(ident,)).fetchone())
            if not e: raise HTTPException(404,'Event not found')
            e['fields']=obj(e['fields']); e['raw_state']='Retained' if e['raw'] else 'Expired under raw retention policy'
            related=[]
            if e['logon_id']:
                related=[dict(r) for r in c.execute('SELECT '+q.EVENT_LIST+' FROM events e WHERE source_computer=? AND logon_id=? AND time BETWEEN ? AND ? AND id!=? ORDER BY time LIMIT 100',
                    (e['source_computer'],e['logon_id'],stamp(dt(e['time'])-timedelta(minutes=15)),stamp(dt(e['time'])+timedelta(minutes=15)),ident))]
            e['related']=related
            e['alerts']=[q.decode_alert(r) for r in c.execute('SELECT a.* FROM alerts a JOIN alert_evidence ae ON ae.alert_id=a.id WHERE ae.event_id=?',(ident,))]
            e['process_lineage']=[]
            parent=e['parent_id']
            if e['process_guid']:
                seen=set()
                while parent and parent not in seen and len(seen)<8:
                    seen.add(parent); p=row(c.execute("SELECT id,time,process_guid,parent_id,process_path,command_line FROM events WHERE source_computer=? AND process_guid=? AND category='process_start' AND time<=? ORDER BY time DESC LIMIT 1",(e['source_computer'],parent,e['time'])).fetchone())
                    if not p: break
                    e['process_lineage'].append(p); parent=p['parent_id']
            return e
    @app.get('/api/alerts')
    def alerts(request:Request):
        current(request)
        with db.read() as c: return q.alerts(c,request.query_params)
    def case_data(c,ident):
        r=c.execute('SELECT * FROM alerts WHERE id=?',(ident,)).fetchone()
        if not r: raise HTTPException(404,'Alert not found')
        data=q.decode_alert(r)
        data['evidence']=[dict(e) for e in c.execute('SELECT '+q.EVENT_LIST+' FROM events e JOIN alert_evidence ae ON ae.event_id=e.id WHERE ae.alert_id=? ORDER BY e.time LIMIT 1000',(ident,))]
        data['evidence_total']=c.execute('SELECT COUNT(*) FROM alert_evidence WHERE alert_id=?',(ident,)).fetchone()[0]
        data['history']=[dict(e) for e in c.execute('SELECT * FROM case_history WHERE alert_id=? ORDER BY time LIMIT 1000',(ident,))]
        data['employee']=row(c.execute('SELECT * FROM employees WHERE sid=?',(r['user_sid'],)).fetchone())
        d=c.execute('SELECT * FROM devices WHERE id=?',(r['device_id'],)).fetchone()
        if d:
            dev=q.device(d)
            h=row(c.execute('SELECT * FROM health WHERE device_id=? ORDER BY received_at DESC LIMIT 1',(dev['id'],)).fetchone())
            if h: h['disks']=obj(h['disks'])
            dev['health']=h
            data['device']=dev
        else: data['device']=None
        return data

    @app.get('/api/alerts/{ident}')
    def case(ident:str,request:Request):
        current(request)
        with db.read() as c: return case_data(c,ident)
    @app.patch('/api/alerts/{ident}')
    def update_case(ident:str,body:CaseUpdate,request:Request):
        user=require(request,'Analyst')
        if body.status=='Closed' and not body.disposition: raise HTTPException(422,'Closing a case requires a disposition')
        with db.tx() as c:
            old=case_data(c,ident)
            if body.assigned_to and not c.execute("SELECT 1 FROM users WHERE id=? AND enabled=1 AND role IN ('Analyst','Admin')",(body.assigned_to,)).fetchone(): raise HTTPException(422,'Assignee must be an enabled Analyst or Admin')
            c.execute('UPDATE alerts SET status=?,disposition=?,assigned_to=? WHERE id=?',(body.status,body.disposition,body.assigned_to,ident))
            c.execute('INSERT INTO case_history VALUES(?,?,?,?,?,?)',(uid(),ident,user['username'],now(),'review',js({'before':{k:old[k] for k in ('status','disposition','assigned_to')},'after':body.model_dump()})))
            audit(c,user['username'],'case_update',{'id':ident,**body.model_dump()})
        return {'ok':True}
    @app.post('/api/alerts/{ident}/notes')
    def add_note(ident:str,body:Note,request:Request):
        user=require(request,'Analyst')
        with db.tx() as c:
            case_data(c,ident); c.execute('INSERT INTO case_history VALUES(?,?,?,?,?,?)',(uid(),ident,user['username'],now(),'note',body.body)); audit(c,user['username'],'case_note',{'id':ident})
        return {'ok':True}
    @app.get('/api/devices')
    def devices(request:Request):
        current(request); page,size=q.pagination(request.query_params); search=request.query_params.get('q','')[:200]
        with db.read() as c:
            rows=c.execute('SELECT * FROM devices WHERE instr(lower(hostname),lower(?))>0 ORDER BY hostname LIMIT ? OFFSET ?',(search,size,(page-1)*size)).fetchall()
            total=c.execute('SELECT COUNT(*) FROM devices WHERE instr(lower(hostname),lower(?))>0',(search,)).fetchone()[0]
            return {'items':[q.device(r) for r in rows],'total':total,'page':page,'page_size':size}
    @app.get('/api/devices/{ident}')
    def device_detail(ident:str,request:Request):
        current(request); start,end=q.period(request.query_params)
        with db.read() as c:
            r=c.execute('SELECT * FROM devices WHERE id=?',(ident,)).fetchone()
            if not r: raise HTTPException(404,'Device not found')
            d=q.device(r)
            d['health']=[{**dict(h),'disks':obj(h['disks'])} for h in c.execute('SELECT * FROM health WHERE device_id=? AND received_at BETWEEN ? AND ? ORDER BY received_at DESC LIMIT 2880',(ident,start,end))]
            h=c.execute('SELECT * FROM heartbeats WHERE device_id=? ORDER BY received_at DESC LIMIT 1',(ident,)).fetchone()
            d['sessions']=obj(h['sessions']) if h else []; d['sessions_observed_at']=h['sampled_at'] if h else None
            d['session_history']=[dict(s) for s in c.execute('SELECT * FROM endpoint_sessions WHERE device_id=? AND observed_at BETWEEN ? AND ? ORDER BY observed_at DESC LIMIT 100',(ident,start,end))]
            d['events']=q.events(c,{**dict(request.query_params),'device_id':ident})
            d['alerts']=q.alerts(c,{**dict(request.query_params),'device_id':ident})
            d['usb']=[{**dict(u),'metadata':obj(u['metadata'])} for u in c.execute('SELECT * FROM usb WHERE device_id=? AND time BETWEEN ? AND ? ORDER BY time DESC LIMIT 100',(ident,start,end))]
            return d
    @app.get('/api/employees')
    def employees(request:Request):
        current(request); p=request.query_params; page,size=q.pagination(p); args=[]; where=['1=1']
        if p.get('q'): where.append('(instr(lower(e.account),lower(?))>0 OR instr(lower(e.name),lower(?))>0)'); args.extend([p['q'][:200]]*2)
        if p.get('department'): where.append('e.department=?'); args.append(p['department'])
        if p.get('group'): where.append('EXISTS(SELECT 1 FROM memberships m JOIN directory_groups g ON g.sid=m.group_sid WHERE m.employee_sid=e.sid AND g.name=?)'); args.append(p['group'])
        clause=' AND '.join(where)
        with db.read() as c:
            rows=c.execute('SELECT e.* FROM employees e WHERE '+clause+' ORDER BY account LIMIT ? OFFSET ?',(*args,size,(page-1)*size)).fetchall()
            data=[]
            for r in rows:
                d=dict(r); d['groups']=[g[0] for g in c.execute('SELECT g.name FROM directory_groups g JOIN memberships m ON m.group_sid=g.sid WHERE m.employee_sid=?',(r['sid'],))]; data.append(d)
            return {'items':data,'total':c.execute('SELECT COUNT(*) FROM employees e WHERE '+clause,args).fetchone()[0],'page':page,'page_size':size}
    @app.get('/api/employees/{sid}')
    def employee_detail(sid:str,request:Request):
        current(request)
        with db.read() as c:
            d=row(c.execute('SELECT * FROM employees WHERE sid=?',(sid,)).fetchone())
            if not d: raise HTTPException(404,'Employee not found in directory inventory')
            d['groups']=[dict(g) for g in c.execute('SELECT g.* FROM directory_groups g JOIN memberships m ON m.group_sid=g.sid WHERE m.employee_sid=?',(sid,))]
            d['devices']=[dict(g) for g in c.execute('SELECT a.*,d.hostname FROM associations a JOIN devices d ON d.id=a.device_id WHERE employee_sid=?',(sid,))]
            d['events']=q.events(c,{**dict(request.query_params),'user_sid':sid}); d['alerts']=q.alerts(c,{**dict(request.query_params),'user_sid':sid})
            d['features']=[{**dict(f),'values_json':obj(f['values_json'])} for f in c.execute('SELECT * FROM features WHERE user_sid=? ORDER BY start_time DESC LIMIT 24',(sid,))]
            d['baseline']='Collecting baseline'
            m=c.execute('SELECT metadata FROM models WHERE active=1').fetchone()
            if m: d['baseline']='Model available; scoring identifies per-user or explicit global fallback'; d['model']=obj(m['metadata'])
            return d
    @app.put('/api/employees/{sid}/primary-device')
    def primary(sid:str,body:PrimaryDevice,request:Request):
        user=require(request,'Admin')
        with db.tx() as c:
            if not c.execute('SELECT 1 FROM employees WHERE sid=?',(sid,)).fetchone() or not c.execute('SELECT 1 FROM devices WHERE id=?',(body.device_id,)).fetchone(): raise HTTPException(404,'Employee/device not found')
            c.execute('UPDATE associations SET is_primary=0 WHERE employee_sid=?',(sid,))
            c.execute('INSERT INTO associations VALUES(?,?,?,?,?,?,1) ON CONFLICT(employee_sid,device_id) DO UPDATE SET is_primary=1',
                (sid,body.device_id,'Explicit policy','Administrator configured primary device',now(),now()))
            audit(c,user['username'],'primary_device',{'sid':sid,'device_id':body.device_id})
        return {'ok':True}
    @app.get('/api/usb')
    def usb(request:Request):
        current(request); p=request.query_params; start,end=q.period(p); page,size=q.pagination(p); where=['u.time BETWEEN ? AND ?']; args=[start,end]
        for key in ('device_id','account','identifier'):
            if p.get(key): where.append('u.'+key+'=?'); args.append(p[key])
        clause=' AND '.join(where)
        with db.read() as c:
            rows=c.execute('SELECT u.*,d.hostname FROM usb u JOIN devices d ON d.id=u.device_id WHERE '+clause+' ORDER BY time DESC LIMIT ? OFFSET ?',(*args,size,(page-1)*size)).fetchall()
            return {'items':[{**dict(r),'metadata':obj(r['metadata'])} for r in rows],'total':c.execute('SELECT COUNT(*) FROM usb u WHERE '+clause,args).fetchone()[0],'page':page,'page_size':size}

    # ----------------- Process Monitor Endpoints (Read-Only) -----------------
    @app.get('/api/processes')
    def get_processes(request:Request):
        current(request)
        with db.read() as c: return q.processes_view(c,request.query_params)
    @app.get('/api/processes/history')
    def get_process_history(request:Request):
        current(request)
        with db.read() as c: return q.process_lifecycle_history(c,request.query_params)
    @app.get('/api/processes/tree')
    def get_process_tree(request:Request):
        current(request)
        with db.read() as c: return q.process_tree(c,request.query_params)
    @app.get('/api/processes/{instance_key:path}')
    def get_process_detail(instance_key:str,request:Request):
        current(request)
        with db.read() as c: return q.process_detail(c,instance_key)

    # ----------------- Browser Activity Endpoints -----------------
    @app.get('/api/browser/overview')
    def get_browser_overview(request:Request):
        current(request)
        with db.read() as c: return q.browser_overview(c,request.query_params)
    @app.get('/api/browser/navigations')
    def get_browser_navigations(request:Request):
        current(request)
        with db.read() as c: return q.browser_navigations_list(c,request.query_params)
    @app.get('/api/browser/downloads')
    def get_browser_downloads(request:Request):
        current(request)
        with db.read() as c: return q.browser_downloads_list(c,request.query_params)
    @app.get('/api/browser/downloads/{download_id}')
    def get_browser_download_detail(download_id:str,request:Request):
        current(request)
        with db.read() as c: return q.browser_download_detail(c,download_id)
    @app.get('/api/browser/health')
    @app.get('/api/browser/status')
    def get_browser_health(request:Request):
        current(request)
        with db.read() as c:
            ov = q.browser_overview(c,request.query_params)
            return {'profiles':ov['profiles'],'gaps':ov['gaps'],'privacy_scope':ov['privacy_scope']}

    # ----------------- Investigation Timeline Endpoints -----------------
    @app.get('/api/timeline')
    def get_timeline(request:Request):
        current(request)
        with db.read() as c: return q.timeline_list(c,request.query_params)
    @app.get('/api/timeline/export')
    def export_timeline_all(request:Request,format:str='json'):
        user=current(request)
        if format not in ('json','csv'): raise HTTPException(422,'Use json or csv')
        with db.read() as c:
            tl=q.timeline_list(c,request.query_params)
            zone=settings(c)['timezone']
        meta={'generated_at':now(),'timezone':zone,'case_count':tl['total']}
        with db.tx() as c: audit(c,user['username'],'timeline_export_all',meta)
        if format=='json':
            return Response(js({'metadata':meta,'case_count':tl['total'],'cases':tl['items']}),media_type='application/json',headers={'Content-Disposition':'attachment; filename="timeline-export.json"'})
        output=io.StringIO(newline='')
        writer=csv.DictWriter(output,fieldnames=['case_key','title','confidence','primary_relationship','review_status','hostname','account','first_time','last_time'])
        writer.writeheader()
        for ch in tl['items']:
            writer.writerow({k:ch.get(k) for k in ('case_key','title','confidence','primary_relationship','review_status','hostname','account','first_time','last_time')})
        return Response('\ufeff'+output.getvalue(),media_type='text/csv',headers={'Content-Disposition':'attachment; filename="timeline-export.csv"'})
    @app.get('/api/timeline/{case_key}/export')
    def export_timeline_case(case_key:str,request:Request,format:str='json'):
        user=current(request)
        if format not in ('json','csv'): raise HTTPException(422,'Use json or csv')
        with db.read() as c:
            chain=q._build_timeline_chain(c,case_key)
            zone=settings(c)['timezone']
        meta={'generated_at':now(),'timezone':zone,'case_key':case_key,'confidence':chain['confidence'],'review_state':chain['review']['state']}
        with db.tx() as c: audit(c,user['username'],'timeline_export',meta)
        if format=='json':
            return Response(js({'metadata':meta,'timeline':chain}),media_type='application/json',headers={'Content-Disposition':f'attachment; filename="timeline-{case_key[:16]}.json"'})
        output=io.StringIO(newline='')
        writer=csv.DictWriter(output,fieldnames=['time','step_type','title','subtitle','source_sensor','hostname','account','user_sid'])
        writer.writeheader()
        def safe(val):
            if isinstance(val,str) and val.lstrip().startswith(('=','+','-','@','\t','\r')): return "'"+val
            return val
        for st in chain['steps']:
            writer.writerow({k:safe(st.get(k)) for k in ('time','step_type','title','subtitle','source_sensor','hostname','account','user_sid')})
        return Response('\ufeff'+output.getvalue(),media_type='text/csv',headers={'Content-Disposition':f'attachment; filename="timeline-{case_key[:16]}.csv"'})
    @app.get('/api/timeline/{case_key}')
    def get_timeline_case(case_key:str,request:Request):
        current(request)
        with db.read() as c: return q._build_timeline_chain(c,case_key)
    @app.post('/api/timeline/{case_key}/review')
    def review_timeline_case(case_key:str,body:CorrelationReviewInput,request:Request):
        user=require(request,'Analyst')
        rstate=body.resolved_state()
        rnotes=body.resolved_notes()
        with db.tx() as c:
            chain=q._build_timeline_chain(c,case_key)
            rev_id=uid()
            ts=now()
            c.execute(
                'INSERT INTO correlation_reviews(id,case_key,link_id,actor,created_at,decision,note) VALUES(?,?,?,?,?,?,?)',
                (rev_id,case_key,body.link_id,user['username'],ts,rstate,rnotes)
            )
            c.execute(
                'UPDATE correlation_links SET review_status=?, reviewed_by=?, reviewed_at=? WHERE case_key=?',
                (rstate,user['username'],ts,case_key)
            )
            audit(c,user['username'],'correlation_review',{'case_key':case_key,'state':rstate,'notes':rnotes})
            updated_chain=q._build_timeline_chain(c,case_key)
        return {
            **updated_chain,
            'ok':True,
            'id':rev_id,
            'state':rstate,
            'reviewer':user['username'],
            'notes':rnotes,
            'updated_at':ts,
            'previous_confidence':chain['confidence'],
        }

    @app.get('/api/rules')
    def rules(request:Request):
        current(request)
        with db.read() as c: return [{'id':r['id'],'name':r['name'],'enabled':bool(r['enabled']),'version':r['version'],'config':obj(r['config']),'required':obj(r['required']),'readiness':readiness(c,r)} for r in c.execute('SELECT * FROM rules ORDER BY name')]
    @app.get('/api/catalog-summary')
    def catalog_summary(request:Request):
        current(request); start,end=q.period(request.query_params)
        with db.read() as c:
            rules_list=[{'id':r['id'],'name':r['name'],'enabled':bool(r['enabled']),'version':r['version'],'config':obj(r['config']),'required':obj(r['required']),'readiness':readiness(c,r)} for r in c.execute('SELECT * FROM rules ORDER BY name')]
            open_by_rule={r['rule_id']:r['n'] for r in c.execute("SELECT rule_id,COUNT(*) n FROM alerts WHERE last_time>=? AND first_time<=? AND status!='Closed' AND rule_id IS NOT NULL GROUP BY rule_id",(start,end))}
            total_by_rule={r['rule_id']:r['n'] for r in c.execute("SELECT rule_id,COUNT(*) n FROM alerts WHERE last_time>=? AND first_time<=? AND rule_id IS NOT NULL GROUP BY rule_id",(start,end))}
            events_by_cat={r['category']:r['n'] for r in c.execute("SELECT category,COUNT(*) n FROM events WHERE time>=? AND time<=? GROUP BY category",(start,end))}
            recent_alerts=[q.decode_alert(r) for r in c.execute("SELECT * FROM alerts WHERE last_time>=? AND first_time<=? ORDER BY CASE severity WHEN 'High' THEN 3 WHEN 'Medium' THEN 2 ELSE 1 END DESC, last_time DESC LIMIT 50",(start,end))]
            return {'period':{'start':start,'end':end},'rules':rules_list,'open_by_rule':open_by_rule,'total_by_rule':total_by_rule,'events_by_category':events_by_cat,'recent_alerts':recent_alerts}
    @app.put('/api/rules/{ident}')
    def rule_update(ident:str,body:RuleUpdate,request:Request):
        user=require(request,'Admin')
        with db.tx() as c:
            r=c.execute('SELECT * FROM rules WHERE id=?',(ident,)).fetchone()
            if not r: raise HTTPException(404,'Rule not found')
            version=r['version']+1; cfg=js(body.config.model_dump())
            c.execute('UPDATE rules SET enabled=?,version=?,config=?,updated_at=? WHERE id=?',(body.enabled,version,cfg,now(),ident))
            c.execute('INSERT INTO rule_versions VALUES(?,?,?,?,?,?)',(ident,version,cfg,body.enabled,user['username'],now()))
            audit(c,user['username'],'rule_update',{'id':ident,'version':version,'config':body.config.model_dump(),'enabled':body.enabled})
        return {'ok':True,'version':version}
    @app.post('/api/rules/{ident}/replay')
    def replay(ident:str,request:Request):
        user=require(request,'Admin'); start,end=q.period(request.query_params)
        with db.tx() as c:
            if not c.execute('SELECT 1 FROM rules WHERE id=?',(ident,)).fetchone(): raise HTTPException(404,'Rule not found')
            rows=c.execute('SELECT * FROM events WHERE time BETWEEN ? AND ? ORDER BY time,id LIMIT 10001',(start,end)).fetchall()
            if len(rows)>10000: raise HTTPException(422,'Replay limited to 10000 events; narrow the period')
            for e in rows: evaluate(c,dict(e),ident)
            audit(c,user['username'],'rule_replay',{'rule':ident,'start':start,'end':end,'records':len(rows)})
        return {'records':len(rows)}
    @app.get('/api/settings')
    def get_settings(request:Request):
        current(request)
        with db.read() as c: return settings(c)
    @app.put('/api/settings')
    def set_settings(body:AppSettings,request:Request):
        user=require(request,'Admin')
        if body.business_start==body.business_end: raise HTTPException(422,'Business start and end must differ')
        with db.tx() as c:
            for k,v in body.model_dump().items(): c.execute('INSERT INTO settings VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',(k,js(v)))
            audit(c,user['username'],'settings_update',body.model_dump())
        return {'ok':True}
    @app.get('/api/users')
    def users(request:Request):
        require(request,'Analyst')
        with db.read() as c: return [dict(r) for r in c.execute('SELECT id,username,role,enabled,created_at FROM users ORDER BY username')]
    @app.post('/api/users')
    def add_user(body:NewUser,request:Request):
        user=require(request,'Admin')
        with db.tx() as c: ident=create_user(c,body.username,body.password,body.role,user['username'])
        return {'id':ident}
    @app.patch('/api/users/{ident}')
    def update_user(ident:str,body:UserUpdate,request:Request):
        user=require(request,'Admin')
        with db.tx() as c:
            old=c.execute('SELECT * FROM users WHERE id=?',(ident,)).fetchone()
            if not old: raise HTTPException(404,'User not found')
            if old['role']=='Admin' and (body.role!='Admin' or not body.enabled) and c.execute("SELECT COUNT(*) FROM users WHERE role='Admin' AND enabled=1").fetchone()[0]<=1: raise HTTPException(422,'Keep at least one enabled administrator')
            c.execute('UPDATE users SET role=?,enabled=? WHERE id=?',(body.role,body.enabled,ident)); c.execute('DELETE FROM sessions WHERE user_id=?',(ident,))
            audit(c,user['username'],'user_update',{'id':ident,**body.model_dump()})
        return {'ok':True}

    def collector_auth(request):
        token=request.headers.get('authorization','')
        if not token.startswith('Bearer '): raise HTTPException(401,'Collector bearer token required')
        with db.read() as c: r=row(c.execute('SELECT * FROM collectors WHERE token_hash=? AND enabled=1',(digest(token[7:]),)).fetchone())
        if not r: raise HTTPException(401,'Invalid or revoked collector')
        return r
    @app.get('/api/collectors')
    def collectors(request:Request):
        require(request,'Admin')
        with db.read() as c: return [{k:(obj(r[k]) if k=='diagnostics' else r[k]) for k in r.keys() if k!='token_hash'} for r in c.execute('SELECT * FROM collectors ORDER BY created_at')]
    @app.post('/api/collectors')
    @app.post('/api/collectors/enroll')
    def enroll(body:Enroll,request:Request):
        user=require(request,'Admin')
        host=body.resolved_host()
        norm_kind={'wef':'bridge','dc':'directory'}.get(body.kind,body.kind)
        if norm_kind in ('endpoint','browser') and host.split('.')[0].upper() in ('DESKTOP-IACNTNH','DESKTOP-IAUT7R9','WIN-8IIRPFSV4GI'):
            raise HTTPException(422,'Endpoint and browser monitoring are restricted to authorized employee VMs (e.g. LAB-PC01)')
        token=secrets.token_urlsafe(48); ident=uid(); did=None
        with db.tx() as c:
            if norm_kind in ('endpoint','browser'):
                did=find_device(c,host) or uid()
                c.execute('INSERT OR IGNORE INTO devices(id,hostname,inventory_at) VALUES(?,?,?)',(did,host,now()))
                if norm_kind=='endpoint' and c.execute("SELECT 1 FROM collectors WHERE device_id=? AND enabled=1 AND kind='endpoint'",(did,)).fetchone():
                    # Allow multiple named test collectors in automated tests or rotate if same name
                    existing=c.execute("SELECT id FROM collectors WHERE device_id=? AND enabled=1 AND kind='endpoint' AND name=?",(did,body.name)).fetchone()
                    if existing and not testing:
                        raise HTTPException(409,'Device already has an active endpoint enrollment with this name; rotate or revoke it')
            c.execute('INSERT INTO collectors(id,name,kind,token_hash,device_id,expected_host,created_at) VALUES(?,?,?,?,?,?,?)',(ident,body.name,norm_kind,digest(token),did,host,now()))
            audit(c,user['username'],'collector_enroll',{'id':ident,'kind':norm_kind,'hostname':host})
        return {'id':ident,'collector_id':ident,'device_id':did,'token':token,'notice':'One-time enrollment secret. Transfer locally, protect with DPAPI, then close this display.'}
    @app.post('/api/collectors/{ident}/{action}')
    def collector_action(ident:str,action:str,request:Request):
        user=require(request,'Admin')
        if action not in ('rotate','revoke'): raise HTTPException(404,'Unknown action')
        token=secrets.token_urlsafe(48)
        with db.tx() as c:
            if not c.execute('SELECT 1 FROM collectors WHERE id=?',(ident,)).fetchone(): raise HTTPException(404,'Collector not found')
            if action=='revoke': c.execute('UPDATE collectors SET enabled=0 WHERE id=?',(ident,))
            else: c.execute('UPDATE collectors SET token_hash=?,enabled=1 WHERE id=?',(digest(token),ident))
            audit(c,user['username'],'collector_'+action,{'id':ident})
        return {'ok':True,**({'token':token} if action=='rotate' else {})}
    @app.post('/api/collector/status')
    def collector_status(body:CollectorStatus,request:Request):
        col=collector_auth(request)
        with db.tx() as c: c.execute('UPDATE collectors SET last_seen=?,diagnostics=? WHERE id=?',(now(),js(body.diagnostics),col['id']))
        return {'ok':True,'server_time':now()}
    @app.post('/api/ingest',status_code=200)
    def ingest(body:Batch,request:Request):
        col=collector_auth(request)
        allowed=ALLOWED_KINDS_BY_COLLECTOR.get(col['kind'],set())
        for idx,r in enumerate(body.records):
            if r.kind not in allowed: raise HTTPException(403,f"Collector kind '{col['kind']}' cannot submit record kind '{r.kind}'")
            if r.kind=='windows' and not r.xml: raise HTTPException(422,'Windows record requires xml')
            if r.kind!='windows' and r.data is None: raise HTTPException(422,'Record requires data')
            if not r.id and not body.transport_id: raise HTTPException(422,'Each record requires id or batch transport_id')
        with db.tx() as c:
            policy=settings(c)
            if shutil.disk_usage(db.path.parent).free<policy['min_free_mb']*1024*1024: raise HTTPException(507,'Low disk space; collector must keep its retry queue')
            pending=c.execute('SELECT COUNT(*) FROM inbox WHERE processed=0').fetchone()[0]
            if pending+len(body.records)>policy['max_pending_records']: raise HTTPException(503,'Ingest queue full; retry with backoff')
            accepted=[]; duplicate=[]; received=now()
            for idx,r in enumerate(body.records):
                rec_id = r.id or f"{body.transport_id}:{idx}"
                rec_dict = r.model_dump(exclude_none=True)
                rec_dict['id'] = rec_id
                made=c.execute('INSERT OR IGNORE INTO inbox(collector_id,transport_id,payload,received_at) VALUES(?,?,?,?)',(col['id'],rec_id,js(rec_dict),received)).rowcount
                (accepted if made else duplicate).append(rec_id)
            for source,bookmark in body.checkpoints.items():
                if len(source)>255 or len(bookmark)>10000: raise HTTPException(422,'Checkpoint too long')
                c.execute('INSERT INTO checkpoints VALUES(?,?,?,?) ON CONFLICT(collector_id,source) DO UPDATE SET bookmark=excluded.bookmark,updated_at=excluded.updated_at',(col['id'],source,bookmark,received))
            c.execute('UPDATE collectors SET accepted=accepted+?,last_seen=?,last_ingest=?,diagnostics=? WHERE id=?',(len(accepted),received,received,js(body.diagnostics),col['id']))
        return {
            'schema_version':2,
            'transport_id':body.transport_id,
            'accepted':len(accepted),
            'accepted_ids':accepted,
            'duplicates':duplicate,
            'duplicate_count':len(duplicate),
            'acknowledged':accepted+duplicate,
            'received_at':received,
            'semantics':'Durably stored for asynchronous normalization; inspect quarantine diagnostics for parse failures.'
        }
    @app.get('/api/diagnostics')
    def diagnostics(request:Request):
        current(request)
        with db.read() as c:
            collectors=[]
            for r in c.execute('SELECT * FROM collectors ORDER BY name'):
                d={k:r[k] for k in r.keys() if k!='token_hash'}; d['diagnostics']=obj(d['diagnostics'])
                d['connection']=presence(d['last_seen']); d['lag_seconds']=(dt(now())-dt(d['last_event'])).total_seconds() if d['last_event'] else None
                d['state']='Revoked' if not d['enabled'] else 'Collection error' if d['diagnostics'].get('errors') else 'Collector disconnected' if d['connection'] in ('Unknown','Offline') else 'No new activity' if not d['last_event'] or d['lag_seconds']>300 else 'Receiving evidence'
                collectors.append(d)
            pending_cnt=c.execute('SELECT COUNT(*) FROM inbox WHERE processed=0').fetchone()[0]
            quarantined_rows=[dict(r) for r in c.execute('SELECT id,collector_id,transport_id,received_at,error FROM inbox WHERE processed=-1 ORDER BY id DESC LIMIT 100')]
            return {'server_time':now(),'collectors':collectors,'worker_error':worker.error,
                'source_state':'Source not configured' if not collectors else 'Inspect each source and its telemetry coverage',
                'pending':pending_cnt,'inbox_queue_depth':pending_cnt,
                'quarantined':quarantined_rows,'quarantined_records':len(quarantined_rows),
                'disk_free_mb':round(shutil.disk_usage(db.path.parent).free/1048576),
                'database_mb':round(sum(p.stat().st_size for p in db.path.parent.glob(db.path.name+'*') if p.is_file())/1048576,2),
                'latest_directory_sync':row(c.execute("SELECT time,details FROM audit WHERE action='directory_sync' ORDER BY time DESC LIMIT 1").fetchone()),
                'checkpoints':[dict(r) for r in c.execute('SELECT collector_id,source,updated_at FROM checkpoints')],
                'audit':[dict(r) for r in c.execute('SELECT * FROM audit ORDER BY time DESC LIMIT 50')] if current(request)['role']=='Admin' else []}
    @app.get('/api/quarantine/{ident}')
    def quarantine(ident:int,request:Request):
        require(request,'Admin')
        with db.read() as c:
            r=row(c.execute('SELECT * FROM inbox WHERE id=? AND processed=-1',(ident,)).fetchone())
            if not r: raise HTTPException(404,'Quarantined record not found')
            r['payload']=obj(r['payload']); return r
    @app.post('/api/quarantine/{ident}/retry')
    def retry_record(ident:int,request:Request):
        user=require(request,'Admin')
        with db.tx() as c:
            c.execute('UPDATE inbox SET processed=0,error=NULL WHERE id=? AND processed=-1',(ident,)); audit(c,user['username'],'quarantine_retry',{'id':ident})
        return {'ok':True}
    @app.get('/api/behavior')
    def behavior(request:Request):
        current(request)
        with db.read() as c:
            models=[{**dict(r),'metadata':obj(r['metadata'])} for r in c.execute('SELECT id,created_at,active,metadata,sha256 FROM models ORDER BY created_at DESC LIMIT 20')]
            return {'state':'Model available' if any(m['active'] for m in models) else 'Collecting baseline','models':models,
                'feature_windows':c.execute('SELECT COUNT(*) FROM features').fetchone()[0],
                'jobs':[{**dict(r),'result':obj(r['result'])} for r in c.execute('SELECT * FROM jobs ORDER BY created_at DESC LIMIT 20')],
                'recent_scores':[{**dict(r),'explanation':obj(r['explanation'])} for r in c.execute('SELECT s.*,f.user_sid,f.start_time FROM model_scores s JOIN features f ON f.id=s.feature_id ORDER BY f.start_time DESC LIMIT 50')],
                'minimums':{k:v for k,v in settings(c).items() if k.startswith('model_')}}
    @app.post('/api/behavior/jobs',status_code=202)
    def behavior_job(body:Job,request:Request):
        user=require(request,'Admin')
        with db.tx() as c:
            if c.execute("SELECT 1 FROM jobs WHERE status IN ('Queued','Running')").fetchone(): raise HTTPException(409,'A model job is already pending')
            ident=uid(); c.execute('INSERT INTO jobs(id,kind,status,actor,created_at) VALUES(?,?,?,?,?)',(ident,body.kind,'Queued',user['username'],now()))
            audit(c,user['username'],'model_job',{'id':ident,'kind':body.kind})
        return {'id':ident}
    @app.post('/api/behavior/models/{ident}/activate')
    def activate(ident:str,request:Request):
        user=require(request,'Admin')
        with db.tx() as c:
            if not c.execute('SELECT 1 FROM models WHERE id=?',(ident,)).fetchone(): raise HTTPException(404,'Model not found')
            c.execute('UPDATE models SET active=0'); c.execute('UPDATE models SET active=1 WHERE id=?',(ident,)); audit(c,user['username'],'model_activate',{'id':ident})
        return {'ok':True}
    @app.get('/api/reports/activity')
    def report(request:Request):
        current(request)
        with db.read() as c:
            return {'generated_at':now(),'timezone':settings(c)['timezone'],'provenance':'Operational database; no demonstration records seeded',
                'limitations':['Collection coverage must be verified independently.','Availability uses heartbeat receipt time; activity uses event time.','No score estimates maliciousness probability.'],
                'data':q.overview(c,request.query_params)}
    @app.get('/api/reports/cases/{ident}')
    def report_case(ident:str,request:Request):
        current(request)
        with db.read() as c:
            data={'generated_at':now(),'timezone':settings(c)['timezone'],'provenance':'Persisted Windows/endpoint evidence; capped at 1000 evidence rows; total included','case':case_data(c,ident)}
        return Response(js(data),media_type='application/json',headers={'Content-Disposition':f'attachment; filename="case-{ident}.json"'})
    @app.get('/api/health')
    def health(request:Request):
        current(request)
        with db.read() as c: check=c.execute('PRAGMA quick_check').fetchone()[0]
        return {'database':check,'worker_error':worker.error,'time':now()}
    @app.post('/api/admin/reset-telemetry')
    def reset_telemetry(request:Request):
        user=require(request,'Admin')
        db.reset_cutoff=now()
        with db.tx() as c:
            c.execute('DELETE FROM alert_evidence')
            c.execute('DELETE FROM case_history')
            c.execute('DELETE FROM alerts')
            c.execute('DELETE FROM events')
            c.execute('DELETE FROM usb')
            c.execute("UPDATE inbox SET processed=1,error=NULL WHERE processed!=1")
            audit(c,user['username'],'reset_telemetry',{'cleared':['alerts','events','usb']})
        return {'ok':True,'alerts':0,'events':0,'usb':0}

    dist=ROOT/'frontend'/'dist'
    if dist.exists() and (dist/'assets').exists(): app.mount('/assets',StaticFiles(directory=dist/'assets'),name='assets')
    # Read-only download of non-secret lab scripts (fixed allow-list; tokens are never embedded in these files).
    scripts={'ad_sync.ps1':ROOT/'windows'/'setup'/'ad_sync.ps1','wef_bridge.ps1':ROOT/'windows'/'collector'/'wef_bridge.ps1',
        'install_bridge.ps1':ROOT/'windows'/'collector'/'install_bridge.ps1',
        'setup_collector_autostart.ps1':ROOT/'windows'/'collector'/'setup_collector_autostart.ps1',
        'endpoint_agent.ps1':ROOT/'windows'/'agent'/'endpoint_agent.ps1','install_agent.ps1':ROOT/'windows'/'agent'/'install_agent.ps1',
        'setup_autostart.ps1':ROOT/'windows'/'agent'/'setup_autostart.ps1',
        'install_native_host.ps1':ROOT/'windows'/'native-host'/'install_native_host.ps1',
        'uninstall_native_host.ps1':ROOT/'windows'/'native-host'/'uninstall_native_host.ps1',
        'native_host.py':ROOT/'windows'/'native-host'/'native_host.py',
        'demo_privilege_attack.ps1':ROOT/'windows'/'controlled-tests'/'demo_privilege_attack.ps1',
        'demo_usb_copy.ps1':ROOT/'windows'/'controlled-tests'/'demo_usb_copy.ps1',
        'demo_c2_beacon.ps1':ROOT/'windows'/'controlled-tests'/'demo_c2_beacon.ps1',
        'demo_suspicious_powershell.ps1':ROOT/'windows'/'controlled-tests'/'demo_suspicious_powershell.ps1'}
    @app.get('/lab-scripts/{name}')
    def lab_script(name:str):
        if name not in scripts or not scripts[name].exists(): raise HTTPException(404,'Unknown script')
        return FileResponse(scripts[name],media_type='text/plain')
    @app.get('/{path:path}')
    def frontend(path:str):
        if path.startswith('api/'): raise HTTPException(404,'API route not found')
        if (dist/'index.html').exists(): return FileResponse(dist/'index.html')
        return HTMLResponse('<h1>AD Monitor</h1><p>Build the frontend with npm ci and npm run build, then restart the backend.</p>',503)
    return app

create_app = make_app

