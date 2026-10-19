"""Process Monitor, Browser Activity (MV3 + Native Host), and Deterministic Correlation Engine.
All collection is read-only, scoped to enrolled employee VMs/profiles, and preserves honest provenance.
"""
from __future__ import annotations
import ntpath, posixpath, re, shlex
from datetime import timedelta
from urllib.parse import urlparse
from .db import now, dt, stamp, js, obj, uid, digest, row, settings, presence
from .normalize import canonical

SENSITIVE_ARG_PATTERNS = [
    (re.compile(r'((?:-p(?:assword|ass)?|/p(?:assword|ass)?|--password|--token|--secret|--api-key|-apikey)\s+)(?:"[^"]*"|\'[^\']*\'|\S+)', re.IGNORECASE), r'\1[REDACTED]'),
    (re.compile(r'((?:password|passwd|pwd|secret|token|apikey|api_key|authorization|bearer)\s*[=:]\s*)(?:"[^"]*"|\'[^\']*\'|\S+)', re.IGNORECASE), r'\1[REDACTED]'),
    (re.compile(r'(Bearer\s+)[A-Za-z0-9._~+/=-]+', re.IGNORECASE), r'\1[REDACTED]'),
    (re.compile(r'(ConvertTo-SecureString\s+(?:-String\s+)?)(?:"[^"]*"|\'[^\']*\'|\S+)', re.IGNORECASE), r'\1[REDACTED]'),
    (re.compile(r'((?:-EncodedCommand|-enc|-ec)\s+)[A-Za-z0-9+/=]{16,}', re.IGNORECASE), r'\1[REDACTED]'),
    (re.compile(r'(https?://[^/\s:@]+:)([^@\s/]+)(@)', re.IGNORECASE), r'\1[REDACTED]\3'),
]

SCRIPT_EXTENSIONS = ('.ps1', '.bat', '.cmd', '.vbs', '.js', '.py', '.wsf', '.hta')
EXECUTABLE_EXTENSIONS = ('.exe', '.msi', '.scr', '.com', '.dll')
INTERPRETER_NAMES = {'powershell.exe', 'pwsh.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe', 'python.exe', 'pythonw.exe', 'mshta.exe'}

def redact_command_line(cmd: str | None, state_hint: str | None = None) -> tuple[str | None, str]:
    if cmd is None:
        return None, state_hint if state_hint in ('Not collected', 'Access denied', 'Unavailable') else 'Not collected'
    text = str(cmd).strip()
    if not text:
        return None, state_hint or 'Unavailable'
    redacted = text
    changed = False
    for pattern, repl in SENSITIVE_ARG_PATTERNS:
        new_text, count = pattern.subn(repl, redacted)
        if count > 0:
            redacted = new_text
            changed = True
    if len(redacted) > 4000:
        redacted = redacted[:4000] + ' ... [TRUNCATED]'
    return redacted, ('Redacted' if changed else (state_hint if state_hint in ('Collected', 'Redacted') else 'Collected'))

def sanitize_domain_only(raw_url_or_domain: str | None) -> tuple[str | None, str | None, int | None]:
    """Extracts ONLY normalized (domain, scheme, port) for HTTP/HTTPS.
    Rejects non-HTTP/HTTPS schemes and strips credentials, path, query, and fragment BEFORE persistence.
    """
    if not raw_url_or_domain or not isinstance(raw_url_or_domain, str):
        return None, None, None
    raw = raw_url_or_domain.strip()
    if not raw:
        return None, None, None
    # Reject explicit non-web schemes immediately
    lower = raw.casefold()
    for forbidden in ('chrome:', 'edge:', 'about:', 'file:', 'data:', 'javascript:', 'blob:', 'chrome-extension:', 'extension:', 'view-source:', 'devtools:'):
        if lower.startswith(forbidden):
            return None, None, None
    if '://' not in raw:
        if '/' in raw or '?' in raw or '#' in raw or '@' in raw:
            parsed = urlparse('https://' + raw)
        else:
            host = raw.split(':')[0].strip().rstrip('.').casefold()
            if not host or any(c in host for c in (' ', '/', '?', '#', '@', '\\')):
                return None, None, None
            try:
                host = host.encode('idna').decode('ascii')
            except Exception:
                pass
            return host, 'https', None
    else:
        parsed = urlparse(raw)
    scheme = (parsed.scheme or '').casefold()
    if scheme not in ('http', 'https'):
        return None, None, None
    hostname = (parsed.hostname or '').strip().rstrip('.').casefold()
    if not hostname:
        return None, None, None
    try:
        hostname = hostname.encode('idna').decode('ascii')
    except Exception:
        pass
    try:
        port = parsed.port
    except ValueError:
        port = None
    return hostname, scheme, port

def make_instance_key(device_id: str, boot_session_id: str | None, pid: int, creation_time: str | None, process_guid: str | None = None) -> str:
    if process_guid and str(process_guid).strip() and str(process_guid).strip() != '{00000000-0000-0000-0000-000000000000}':
        return digest(f"proc_guid:{device_id}:{str(process_guid).strip().casefold()}")
    boot = (boot_session_id or 'boot_unknown').strip()
    ctime = (creation_time[:23] if creation_time else 'ctime_unknown')
    return digest(f"proc_pid:{device_id}:{boot}:{int(pid)}:{ctime}")

def resolve_employee_sid(c, user_sid: str | None, account: str | None) -> tuple[str | None, str | None]:
    sid = (user_sid or '').strip() or None
    acct = (account or '').strip() or None
    if sid in ('S-1-0-0', '-'):
        sid = None
    if acct in ('-', ''):
        acct = None
    if not sid and acct:
        short = acct.split('\\')[-1].split('@')[0].casefold()
        rows = c.execute(
            'SELECT sid, account FROM employees WHERE lower(account)=lower(?) OR lower(account) LIKE ?',
            (acct, '%\\' + short)
        ).fetchall()
        if len(rows) == 1:
            sid = rows[0]['sid']
            acct = rows[0]['account']
    elif sid and (not acct or '\\' not in acct):
        u = c.execute('SELECT account FROM employees WHERE sid=?', (sid,)).fetchone()
        if u and u['account']:
            acct = u['account']
    return sid, acct

def extract_referenced_script_paths(command_line: str | None) -> list[dict]:
    """Safely extracts script or executable arguments referenced in an interpreter command line.
    Never equates the interpreter's own binary (e.g. powershell.exe) with a downloaded script.
    Preserves whether the path is absolute or relative/ambiguous.
    """
    if not command_line or not isinstance(command_line, str):
        return []
    text = command_line.strip()
    if not text:
        return []
    results = []
    # Tokenize respecting Windows quotes
    try:
        tokens = shlex.split(text, posix=False)
    except ValueError:
        tokens = text.split()
    cleaned_tokens = []
    for tok in tokens:
        t = tok.strip()
        if len(t) >= 2 and ((t[0] == '"' and t[-1] == '"') or (t[0] == "'" and t[-1] == "'")):
            t = t[1:-1].strip()
        if t:
            cleaned_tokens.append(t)
    if not cleaned_tokens:
        return []

    first_base = ntpath.basename(cleaned_tokens[0]).casefold()
    start_idx = 1 if (first_base in INTERPRETER_NAMES or first_base.endswith('.exe')) else 0

    # Check if there are unquoted tokens that look like a split Windows path with spaces
    unquoted_ambiguity = False
    for idx in range(start_idx, len(cleaned_tokens)):
        tok = cleaned_tokens[idx]
        low = tok.casefold()
        if low in ('-file', '-f', '/c', '/k'):
            if idx + 1 < len(cleaned_tokens):
                candidate = cleaned_tokens[idx + 1]
                # Check if subsequent token also ends with script extension due to unquoted space
                if idx + 2 < len(cleaned_tokens) and not cleaned_tokens[idx + 2].startswith(('-', '/')) and any(cleaned_tokens[idx + 2].casefold().endswith(ext) for ext in SCRIPT_EXTENSIONS):
                    unquoted_ambiguity = True
                is_abs = bool(re.match(r'^[a-zA-Z]:[\\/]', candidate) or candidate.startswith('\\\\'))
                results.append({
                    'raw_path': candidate,
                    'canonical_path': canonical(candidate) if is_abs else None,
                    'relative_tail': candidate.replace('/', '\\').lstrip('.\\').casefold(),
                    'basename': ntpath.basename(candidate).casefold(),
                    'is_absolute': is_abs,
                    'ambiguous_quoting': unquoted_ambiguity,
                    'flag': low
                })
        elif not tok.startswith(('-', '/')) and any(low.endswith(ext) for ext in SCRIPT_EXTENSIONS):
            is_abs = bool(re.match(r'^[a-zA-Z]:[\\/]', tok) or tok.startswith('\\\\'))
            results.append({
                'raw_path': tok,
                'canonical_path': canonical(tok) if is_abs else None,
                'relative_tail': tok.replace('/', '\\').lstrip('.\\').casefold(),
                'basename': ntpath.basename(tok).casefold(),
                'is_absolute': is_abs,
                'ambiguous_quoting': unquoted_ambiguity,
                'flag': 'positional'
            })
    # Deduplicate by raw_path
    dedup = {}
    for r in results:
        dedup[r['raw_path'].casefold()] = r
    return list(dedup.values())

def verify_parent_lineage(c, device_id: str, boot_session_id: str | None, child_creation_time: str | None, parent_pid: int | None, parent_guid: str | None, parent_name: str | None) -> tuple[str | None, str | None, str]:
    """Resolves parent_instance_key ONLY when supported by valid creation evidence.
    Never links a parent merely because its current PID matches an old parent ID.
    """
    if parent_guid and str(parent_guid).strip() and str(parent_guid).strip() != '{00000000-0000-0000-0000-000000000000}':
        row_p = c.execute(
            'SELECT instance_key, name, creation_time FROM process_instances WHERE device_id=? AND lower(process_guid)=lower(?) LIMIT 1',
            (device_id, str(parent_guid).strip())
        ).fetchone()
        if row_p:
            return row_p['instance_key'], row_p['name'] or parent_name, 'Strong: ProcessGuid'
        p_key = make_instance_key(device_id, boot_session_id, int(parent_pid or 0), None, parent_guid)
        return p_key, parent_name, 'Strong: ProcessGuid'

    if parent_pid is None or int(parent_pid) <= 0:
        return None, None, 'Unavailable'

    if not child_creation_time:
        return None, parent_name, 'PID only (parent identity not verified)'

    candidates = c.execute(
        'SELECT instance_key, name, boot_session_id, creation_time, exited_at, no_longer_observed_after '
        'FROM process_instances WHERE device_id=? AND pid=? ORDER BY creation_time DESC',
        (device_id, int(parent_pid))
    ).fetchall()
    for cand in candidates:
        if boot_session_id and cand['boot_session_id'] and cand['boot_session_id'] != boot_session_id:
            continue
        if not cand['creation_time']:
            continue
        # Parent must have started at or before child creation time
        if cand['creation_time'] > child_creation_time:
            continue
        # And must not have exited before child started
        if cand['exited_at'] and cand['exited_at'] < child_creation_time:
            continue
        if parent_name and cand['name'] and cand['name'].casefold() != parent_name.casefold():
            continue
        return cand['instance_key'], cand['name'] or parent_name, 'Verified: creation-time + PID before child start'

    return None, parent_name, 'PID only (parent identity not verified)'

def ingest_process_snapshot(c, payload: dict, collector: dict, received: str, policy: dict):
    data = payload.get('data') or {}
    did = collector['device_id']
    if not did:
        raise ValueError('Process snapshot requires an enrolled device collector')
    host = (data.get('hostname') or '').strip()
    if host and collector.get('expected_host') and host.split('.')[0].casefold() != collector['expected_host'].split('.')[0].casefold():
        raise ValueError('Process snapshot hostname does not match collector enrollment')

    sampled_at = stamp(data.get('sampled_at') or data.get('observed_at') or data.get('time') or payload.get('time') or received)
    if dt(sampled_at) > dt(received) + timedelta(minutes=5):
        raise ValueError('Process snapshot clock more than 5 minutes ahead')

    snap_id = str(data.get('snapshot_id') or payload.get('id') or uid())[:128]
    boot_session_id = str(data.get('boot_session_id') or '').strip() or None
    logical_cpus = max(1, int(data.get('logical_cpus') or 1))
    raw_complete = data['is_complete'] if 'is_complete' in data else data.get('complete', True)
    is_complete = 1 if raw_complete else 0
    raw_bidx = data.get('batch_index')
    raw_btot = data.get('batch_total') if data.get('batch_total') is not None else data.get('batch_count')
    batch_index = max(1, int(raw_bidx) if raw_bidx is not None else 1)
    batch_total = max(batch_index, int(raw_btot) if raw_btot is not None else 1)
    processes = data.get('processes')
    if not isinstance(processes, list):
        raise ValueError('Process snapshot requires a processes list')
    if len(processes) > 500:
        raise ValueError('Process snapshot batch exceeds 500 processes; split into batches')

    errors = data.get('errors') if isinstance(data.get('errors'), list) else []
    total_cpu = data.get('total_cpu_percent')
    if total_cpu is not None:
        total_cpu = round(min(100.0, max(0.0, float(total_cpu))), 1)
    mem_used = int(data['memory_used_bytes']) if data.get('memory_used_bytes') is not None else None
    mem_total = int(data['memory_total_bytes']) if data.get('memory_total_bytes') is not None else None
    raw_dur = data.get('sample_duration_ms') if data.get('sample_duration_ms') is not None else data.get('duration_ms')
    duration_ms = int(raw_dur) if raw_dur is not None else None

    existing_snap = c.execute('SELECT * FROM process_snapshots WHERE id=?', (snap_id,)).fetchone()
    if not existing_snap:
        c.execute(
            'INSERT INTO process_snapshots(id,device_id,collector_id,boot_session_id,sampled_at,received_at,collector_version,'
            'logical_cpus,total_cpu_percent,memory_used_bytes,memory_total_bytes,process_count,is_complete,batch_index,batch_total,sample_duration_ms,errors) '
            'VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
            (snap_id, did, collector['id'], boot_session_id, sampled_at, received, data.get('collector_version'),
             logical_cpus, total_cpu, mem_used, mem_total, len(processes), is_complete, batch_index, batch_total, duration_ms, js(errors))
        )
    else:
        c.execute(
            'UPDATE process_snapshots SET process_count=process_count+?, is_complete=?, batch_index=MAX(batch_index,?), '
            'batch_total=MAX(batch_total,?), received_at=MAX(received_at,?) WHERE id=?',
            (len(processes), is_complete, batch_index, batch_total, received, snap_id)
        )

    # Detect reboot: if boot_session_id changed from previous snapshot on this device, mark older active instances as No longer observed
    if boot_session_id:
        c.execute(
            "UPDATE process_instances SET observed_state='No longer observed', no_longer_observed_after=COALESCE(no_longer_observed_after, ?) "
            "WHERE device_id=? AND boot_session_id IS NOT NULL AND boot_session_id!=? AND observed_state='Observed'",
            (sampled_at, did, boot_session_id)
        )

    observed_keys = set()
    # First pass: create/update instances so parent lookups within the same snapshot can succeed
    prepared = []
    for p in processes:
        if not isinstance(p, dict) or p.get('pid') is None or not p.get('name'):
            continue
        pid = int(p['pid'])
        name = str(p['name']).strip()[:260]
        ctime = stamp(p['creation_time']) if p.get('creation_time') else None
        pguid = str(p.get('process_guid') or '').strip() or None
        ikey = make_instance_key(did, boot_session_id, pid, ctime, pguid)
        observed_keys.add(ikey)
        prepared.append((ikey, pid, name, ctime, pguid, p))

    # Sort by creation_time ascending so parents are registered before children
    prepared.sort(key=lambda item: item[3] or '')

    for ikey, pid, name, ctime, pguid, p in prepared:
        # Handle PID reuse: if another active instance on the same device has the same PID but different instance_key
        c.execute(
            "UPDATE process_instances SET observed_state='No longer observed', no_longer_observed_after=COALESCE(no_longer_observed_after, ?) "
            "WHERE device_id=? AND pid=? AND instance_key!=? AND observed_state='Observed'",
            (sampled_at, did, pid, ikey)
        )

        exe_path = str(p.get('executable_path') or p.get('path') or '').strip() or None
        canon_path = canonical(exe_path, policy.get('path_mappings', ())) if exe_path else None
        cmd_raw = p.get('command_line')
        cmd_state_hint = p.get('command_line_state')
        redacted_cmd, cmd_state = redact_command_line(cmd_raw, cmd_state_hint)

        sid, acct = resolve_employee_sid(c, p.get('user_sid'), p.get('account') or p.get('user'))
        session_id = int(p['session_id']) if p.get('session_id') is not None else None
        parent_pid = int(p['parent_pid']) if p.get('parent_pid') is not None else None
        parent_guid = str(p.get('parent_process_guid') or '').strip() or None
        parent_name = str(p.get('parent_name') or '').strip() or None

        parent_key, resolved_parent_name, parent_conf = verify_parent_lineage(
            c, did, boot_session_id, ctime, parent_pid, parent_guid, parent_name
        )

        sig_state = str(p.get('signature_state') or p.get('signature_status') or 'Not collected')
        if sig_state == 'Signed':
            sig_state = 'Verified'
        elif sig_state == 'Unverified':
            sig_state = 'Invalid'
        if sig_state not in ('Verified', 'Unsigned', 'Invalid', 'Not collected', 'Access denied', 'File changed', 'Unavailable'):
            sig_state = 'Not collected'
        signer = str(p.get('signer') or '').strip() or None
        sha256 = str(p.get('sha256') or '').strip().lower() or None
        hash_state = str(p.get('hash_state') or ('Verified' if sha256 else 'Not collected'))

        id_conf = 'Strong: ProcessGuid' if pguid else ('Verified: Device+Boot+PID+CreationTime' if (boot_session_id and ctime) else ('Moderate: Device+PID+CreationTime' if ctime else 'Weak: PID only (creation time unavailable)'))

        prev_inst = c.execute('SELECT * FROM process_instances WHERE instance_key=?', (ikey,)).fetchone()
        prev_sample = c.execute(
            'SELECT sampled_at, cpu_time_ms FROM process_samples WHERE instance_key=? ORDER BY sampled_at DESC LIMIT 1',
            (ikey,)
        ).fetchone()

        cpu_time_ms = int(p['cpu_time_ms']) if p.get('cpu_time_ms') is not None else None
        cpu_percent = None
        if prev_sample and cpu_time_ms is not None and prev_sample['cpu_time_ms'] is not None:
            elapsed_ms = (dt(sampled_at) - dt(prev_sample['sampled_at'])).total_seconds() * 1000.0
            delta_cpu = cpu_time_ms - int(prev_sample['cpu_time_ms'])
            if elapsed_ms > 0 and delta_cpu >= 0:
                cpu_percent = round(min(100.0, max(0.0, (delta_cpu / (elapsed_ms * logical_cpus)) * 100.0)), 2)

        ws_bytes = int(p['working_set_bytes']) if p.get('working_set_bytes') is not None else None
        priv_bytes = int(p['private_bytes']) if p.get('private_bytes') is not None else None
        handles = int(p['handle_count']) if p.get('handle_count') is not None else None
        threads = int(p['thread_count']) if p.get('thread_count') is not None else None

        raw_meta = {
            'collector_id': collector['id'],
            'snapshot_id': snap_id,
            'boot_session_id': boot_session_id,
            'session_id': session_id,
            'command_line_state': cmd_state,
            'signature_state': sig_state,
            'hash_state': hash_state,
            'identity_confidence': id_conf,
            'parent_confidence': parent_conf
        }

        if not prev_inst:
            c.execute(
                'INSERT INTO process_instances(instance_key,device_id,boot_session_id,pid,process_guid,name,executable_path,canonical_path,'
                'command_line,command_line_state,user_sid,account,session_id,creation_time,parent_instance_key,parent_pid,parent_name,'
                'parent_confidence,identity_confidence,signature_state,signer,sha256,hash_state,first_seen_at,last_seen_at,exited_at,'
                'no_longer_observed_after,observed_state,source_kind,source_event_ids,raw_metadata) '
                'VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                (ikey, did, boot_session_id, pid, pguid, name, exe_path, canon_path,
                 redacted_cmd, cmd_state, sid, acct, session_id, ctime, parent_key, parent_pid, resolved_parent_name,
                 parent_conf, id_conf, sig_state, signer, sha256, hash_state, sampled_at, sampled_at, None,
                 None, 'Observed', 'Snapshot', '[]', js(raw_meta))
            )
        else:
            new_source = 'Snapshot + Lifecycle event' if 'Lifecycle' in prev_inst['source_kind'] else 'Snapshot'
            new_state = 'Exited' if prev_inst['exited_at'] and prev_inst['exited_at'] <= sampled_at else 'Observed'
            c.execute(
                'UPDATE process_instances SET boot_session_id=COALESCE(?,boot_session_id), executable_path=COALESCE(?,executable_path), '
                'canonical_path=COALESCE(?,canonical_path), command_line=COALESCE(?,command_line), '
                'command_line_state=CASE WHEN ?!="Not collected" THEN ? ELSE command_line_state END, '
                'user_sid=COALESCE(?,user_sid), account=COALESCE(?,account), session_id=COALESCE(?,session_id), '
                'parent_instance_key=COALESCE(?,parent_instance_key), parent_pid=COALESCE(?,parent_pid), '
                'parent_name=COALESCE(?,parent_name), parent_confidence=CASE WHEN parent_instance_key IS NULL THEN ? ELSE parent_confidence END, '
                'signature_state=CASE WHEN ?!="Not collected" THEN ? ELSE signature_state END, signer=COALESCE(?,signer), '
                'sha256=COALESCE(?,sha256), hash_state=CASE WHEN ?!="Not collected" THEN ? ELSE hash_state END, '
                'first_seen_at=MIN(first_seen_at,?), last_seen_at=MAX(last_seen_at,?), observed_state=?, '
                'no_longer_observed_after=CASE WHEN ?="Observed" THEN NULL ELSE no_longer_observed_after END, '
                'source_kind=? WHERE instance_key=?',
                (boot_session_id, exe_path, canon_path, redacted_cmd, cmd_state, cmd_state,
                 sid, acct, session_id, parent_key, parent_pid, resolved_parent_name, parent_conf,
                 sig_state, sig_state, signer, sha256, hash_state, hash_state,
                 sampled_at, sampled_at, new_state, new_state, new_source, ikey)
            )

        sample_id = digest(f"{snap_id}:{ikey}")
        c.execute(
            'INSERT OR REPLACE INTO process_samples(id,snapshot_id,instance_key,device_id,sampled_at,cpu_percent,cpu_time_ms,'
            'working_set_bytes,private_bytes,handle_count,thread_count,state_label) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
            (sample_id, snap_id, ikey, did, sampled_at, cpu_percent, cpu_time_ms, ws_bytes, priv_bytes, handles, threads, 'Observed')
        )

        # Correlate newly observed process with downloads
        inst_row = c.execute('SELECT * FROM process_instances WHERE instance_key=?', (ikey,)).fetchone()
        if inst_row:
            correlate_process_instance(c, dict(inst_row), policy)
            evaluate_process_resource_rule(c, dict(inst_row), policy)

    # Mark missing processes as "No longer observed" ONLY when a complete snapshot is assembled
    snap_row = c.execute('SELECT * FROM process_snapshots WHERE id=?', (snap_id,)).fetchone()
    if snap_row and snap_row['is_complete'] == 1 and snap_row['batch_index'] >= snap_row['batch_total']:
        all_keys_in_snap = {
            r['instance_key'] for r in c.execute('SELECT instance_key FROM process_samples WHERE snapshot_id=?', (snap_id,)).fetchall()
        }
        active_rows = c.execute(
            "SELECT instance_key, last_seen_at FROM process_instances WHERE device_id=? AND observed_state='Observed'",
            (did,)
        ).fetchall()
        for r in active_rows:
            if r['instance_key'] not in all_keys_in_snap and r['last_seen_at'] < sampled_at:
                c.execute(
                    "UPDATE process_instances SET observed_state='No longer observed', no_longer_observed_after=? WHERE instance_key=?",
                    (sampled_at, r['instance_key'])
                )

    c.execute('UPDATE devices SET last_event=MAX(COALESCE(last_event,?),?), last_heartbeat=MAX(COALESCE(last_heartbeat,?),?) WHERE id=?', (sampled_at, sampled_at, received, received, did))
    c.execute('UPDATE collectors SET last_event=MAX(COALESCE(last_event,?),?) WHERE id=?', (sampled_at, sampled_at, collector['id']))

def record_lifecycle_from_event(c, event: dict, policy: dict):
    """Bridges normalized Windows 4688/4689 or Sysmon 1/5 events into process_lifecycle_events and process_instances."""
    if event.get('category') not in ('process_start', 'process_end'):
        return
    did = event.get('access_device_id') or event.get('device_id')
    if not did:
        return
    raw_pid = event.get('process_id')
    try:
        pid = int(str(raw_pid), 16 if str(raw_pid).lower().startswith('0x') else 10)
    except (ValueError, TypeError):
        return
    fields = obj(event.get('fields')) or {}
    event_type = 'Started' if event['category'] == 'process_start' else 'Exited'
    when = event['time']
    received = event['received_at']
    pguid = event.get('process_guid') or fields.get('ProcessGuid')
    exe_path = event.get('process_path') or fields.get('NewProcessName') or fields.get('ProcessName') or fields.get('Image')
    name = ntpath.basename(exe_path) if exe_path else str(fields.get('ProcessName') or f'PID-{pid}')
    canon_path = canonical(exe_path, policy.get('path_mappings', ())) if exe_path else None
    redacted_cmd, cmd_state = redact_command_line(event.get('command_line') or fields.get('CommandLine'))
    sid, acct = resolve_employee_sid(c, event.get('user_sid'), event.get('account'))

    parent_pid = None
    if event_type == 'Started':
        for candidate_ppid in (fields.get('ParentProcessId'), event.get('parent_id'), fields.get('ProcessId')):
            if candidate_ppid is None:
                continue
            try:
                parent_pid = int(str(candidate_ppid), 16 if str(candidate_ppid).lower().startswith('0x') else 10)
                break
            except (ValueError, TypeError):
                continue
    parent_guid = fields.get('ParentProcessGuid') if event_type == 'Started' else None
    parent_image = fields.get('ParentImage') or fields.get('ParentProcessName')
    parent_name = ntpath.basename(parent_image) if parent_image else None

    source_channel = f"{'Sysmon' if 'Sysmon' in str(event.get('provider')) else 'Security'}:{event.get('event_id') or ''}"
    ident_key = digest(js([did, event_type, pid, str(pguid or '').casefold(), when[:19], (canon_path or name).casefold()]))

    if c.execute('SELECT 1 FROM process_lifecycle_events WHERE identity_key=?', (ident_key,)).fetchone():
        return

    # Find or create matching process_instances row
    existing_inst = None
    if pguid:
        existing_inst = c.execute('SELECT * FROM process_instances WHERE device_id=? AND lower(process_guid)=lower(?)', (did, str(pguid))).fetchone()
    if not existing_inst:
        # Match by PID on same device within plausible window (including out-of-order Exited before Started)
        candidates = c.execute(
            'SELECT * FROM process_instances WHERE device_id=? AND pid=? ORDER BY last_seen_at DESC LIMIT 5',
            (did, pid)
        ).fetchall()
        for cand in candidates:
            if event_type == 'Started' and cand['creation_time'] and abs((dt(cand['creation_time']) - dt(when)).total_seconds()) <= 5:
                existing_inst = cand
                break
            elif event_type == 'Started' and not cand['creation_time'] and cand['exited_at'] and cand['exited_at'] >= when:
                existing_inst = cand
                break
            elif event_type == 'Exited' and (not cand['creation_time'] or cand['creation_time'] <= when) and not cand['exited_at']:
                existing_inst = cand
                break

    if existing_inst:
        ikey = existing_inst['instance_key']
        ev_ids = obj(existing_inst['source_event_ids']) or []
        if event['id'] not in ev_ids:
            ev_ids.append(event['id'])
        new_source = 'Snapshot + Lifecycle event' if 'Snapshot' in existing_inst['source_kind'] else 'Lifecycle event'
        if event_type == 'Started':
            parent_key, resolved_pname, parent_conf = verify_parent_lineage(c, did, existing_inst['boot_session_id'], when, parent_pid, parent_guid, parent_name)
            c.execute(
                'UPDATE process_instances SET process_guid=COALESCE(?,process_guid), executable_path=COALESCE(?,executable_path), '
                'canonical_path=COALESCE(?,canonical_path), command_line=COALESCE(?,command_line), '
                'command_line_state=CASE WHEN ?!="Not collected" THEN ? ELSE command_line_state END, '
                'user_sid=COALESCE(?,user_sid), account=COALESCE(?,account), creation_time=COALESCE(creation_time,?), '
                'parent_instance_key=COALESCE(?,parent_instance_key), parent_pid=COALESCE(?,parent_pid), '
                'parent_name=COALESCE(?,parent_name), parent_confidence=CASE WHEN parent_instance_key IS NULL THEN ? ELSE parent_confidence END, '
                'first_seen_at=MIN(first_seen_at,?), source_kind=?, source_event_ids=? WHERE instance_key=?',
                (pguid, exe_path, canon_path, redacted_cmd, cmd_state, cmd_state, sid, acct, when,
                 parent_key, parent_pid, resolved_pname, parent_conf, when, new_source, js(ev_ids), ikey)
            )
        else:
            c.execute(
                "UPDATE process_instances SET exited_at=?, last_seen_at=MAX(last_seen_at,?), observed_state='Exited', "
                "source_kind=?, source_event_ids=? WHERE instance_key=?",
                (when, when, new_source, js(ev_ids), ikey)
            )
    else:
        ctime = when if event_type == 'Started' else None
        ikey = make_instance_key(did, None, pid, ctime or when, pguid)
        parent_key, resolved_pname, parent_conf = verify_parent_lineage(c, did, None, ctime, parent_pid, parent_guid, parent_name) if event_type == 'Started' else (None, None, 'Unavailable')
        id_conf = 'Strong: ProcessGuid' if pguid else ('Verified: Lifecycle Event 4688' if event_type == 'Started' else 'Lifecycle Exit 4689 (start not observed)')
        obs_state = 'Observed' if event_type == 'Started' else 'Exited'
        c.execute(
            'INSERT OR IGNORE INTO process_instances(instance_key,device_id,boot_session_id,pid,process_guid,name,executable_path,canonical_path,'
            'command_line,command_line_state,user_sid,account,session_id,creation_time,parent_instance_key,parent_pid,parent_name,'
            'parent_confidence,identity_confidence,signature_state,signer,sha256,hash_state,first_seen_at,last_seen_at,exited_at,'
            'no_longer_observed_after,observed_state,source_kind,source_event_ids,raw_metadata) '
            'VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
            (ikey, did, None, pid, pguid, name, exe_path, canon_path,
             redacted_cmd, cmd_state, sid, acct, None, ctime, parent_key, parent_pid, resolved_pname,
             parent_conf, id_conf, 'Not collected', None, None, 'Not collected', when, when,
             when if event_type == 'Exited' else None, None, obs_state, 'Lifecycle event', js([event['id']]), js({'source_channel': source_channel}))
        )

    c.execute(
        'INSERT INTO process_lifecycle_events(id,event_id,device_id,instance_key,event_type,event_time,received_at,pid,process_guid,'
        'name,executable_path,canonical_path,command_line,command_line_state,user_sid,account,parent_pid,parent_process_guid,parent_image,'
        'exit_code,source_channel,identity_key,raw_metadata) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
        (uid(), event['id'], did, ikey, event_type, when, received, pid, pguid, name, exe_path, canon_path,
         redacted_cmd, cmd_state, sid, acct, parent_pid, parent_guid, parent_image, fields.get('Status') or fields.get('ExitStatus'),
         source_channel, ident_key, js({'event_id': event.get('event_id'), 'provider': event.get('provider')}))
    )

    if event_type == 'Started':
        inst_row = c.execute('SELECT * FROM process_instances WHERE instance_key=?', (ikey,)).fetchone()
        if inst_row:
            correlate_process_instance(c, dict(inst_row), policy)

def ingest_process_lifecycle(c, payload: dict, collector: dict, received: str, policy: dict):
    """Ingests explicit process_lifecycle records sent by the endpoint agent."""
    data = payload.get('data') or {}
    did = collector['device_id']
    if not did:
        raise ValueError('Process lifecycle record requires an enrolled device collector')
    event_type = data.get('event_type')
    if event_type not in ('Started', 'Exited'):
        raise ValueError('process_lifecycle event_type must be Started or Exited')
    when = stamp(data.get('event_time') or data.get('time') or payload.get('time') or received)
    pid = int(data['pid'])
    name = str(data.get('name') or ntpath.basename(str(data.get('executable_path') or f'PID-{pid}')))
    exe_path = str(data.get('executable_path') or '').strip() or None
    sid, acct = resolve_employee_sid(c, data.get('user_sid'), data.get('account'))
    synth_event = {
        'id': str(payload.get('id') or uid()),
        'time': when,
        'received_at': received,
        'event_id': data.get('event_id') or (4688 if event_type == 'Started' else 4689),
        'provider': data.get('provider') or 'ADMonitor.ProcessLifecycle',
        'device_id': did,
        'access_device_id': did,
        'category': 'process_start' if event_type == 'Started' else 'process_end',
        'process_id': str(pid),
        'process_guid': data.get('process_guid'),
        'parent_id': str(data['parent_pid']) if data.get('parent_pid') is not None else None,
        'process_path': exe_path or name,
        'command_line': data.get('command_line'),
        'user_sid': sid,
        'account': acct,
        'fields': js({
            'ParentProcessGuid': data.get('parent_process_guid'),
            'ParentProcessName': data.get('parent_name'),
            'ExitStatus': data.get('exit_code')
        })
    }
    # Also insert into events table if not already present so alert_evidence FK constraints can reference it
    ident = digest(js(['lifecycle', did, event_type, pid, when, exe_path or name]))
    c.execute(
        'INSERT OR IGNORE INTO events(id,identity,time,received_at,event_id,provider,channel,source_computer,collector_id,'
        'source_record,user_sid,account,logon_id,device_id,access_device_id,attribution,category,result,object_path,canonical_path,'
        'source_address,process_id,process_guid,parent_id,process_path,command_line,fields,raw,evidence_type,late_seconds,rules_done) '
        'VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1)',
        (synth_event['id'], ident, when, received, synth_event['event_id'], synth_event['provider'], 'Security',
         collector.get('expected_host') or 'LAB-PC01', collector['id'], synth_event['id'], sid, acct, None, did, did,
         'Strong: endpoint lifecycle sensor', synth_event['category'], 'observed', exe_path,
         canonical(exe_path, policy.get('path_mappings', ())) if exe_path else None, None, str(pid),
         data.get('process_guid'), synth_event['parent_id'], exe_path,
         redact_command_line(data.get('command_line'))[0], synth_event['fields'], js(payload), 'process_lifecycle',
         (dt(received) - dt(when)).total_seconds())
    )
    record_lifecycle_from_event(c, synth_event, policy)

def _verify_browser_profile_context(c, data: dict, collector: dict, received: str) -> dict:
    """Validates that the browser record comes from an authorized collector and OS-verified Windows SID."""
    did = collector['device_id']
    if not did:
        raise ValueError('Browser telemetry requires a device-bound collector')
    profile_id = str(data.get('profile_id') or '').strip()
    if not profile_id or len(profile_id) < 8 or len(profile_id) > 128:
        raise ValueError('Valid opaque browser profile_id required')

    os_sid = str(data.get('user_sid') or '').strip()
    os_account = str(data.get('account') or '').strip()
    sid, acct = resolve_employee_sid(c, os_sid, os_account)
    if not sid or not sid.startswith('S-1-5-21-'):
        raise ValueError('Browser telemetry requires a verified domain Windows user SID (S-1-5-21-...) from the native host OS context')
    if not acct:
        acct = os_account or sid

    raw_bname = str(data.get('browser_name') or 'Chrome').strip()
    if 'edge' in raw_bname.casefold():
        browser_name = 'Edge'
    elif 'chrome' in raw_bname.casefold() or 'chromium' in raw_bname.casefold():
        browser_name = 'Chrome'
    else:
        browser_name = raw_bname
    if browser_name not in ('Chrome', 'Edge'):
        raise ValueError('Unsupported browser_name; must be Chrome or Edge')
    ext_id = str(data.get('extension_id') or data.get('caller_origin') or '').strip()
    if not ext_id:
        raise ValueError('extension_id required')

    prof = c.execute('SELECT * FROM browser_profiles WHERE profile_id=?', (profile_id,)).fetchone()
    if prof:
        if prof['enrollment_state'] == 'Revoked':
            raise ValueError('Browser profile enrollment has been revoked')
        if prof['device_id'] != did or prof['user_sid'] != sid:
            raise ValueError('Browser profile identity mismatch against bound device_id / user_sid')
        c.execute(
            'UPDATE browser_profiles SET last_seen_at=?, last_delivery_at=?, browser_version=COALESCE(?,browser_version), '
            'extension_version=COALESCE(?,extension_version), native_host_version=COALESCE(?,native_host_version), '
            'dropped_count=MAX(dropped_count,?), queue_depth=? WHERE profile_id=?',
            (received, received, data.get('browser_version'), data.get('extension_version'),
             data.get('native_host_version'), int(data.get('dropped_count') or 0), int(data.get('queue_depth') or 0), profile_id)
        )
        return dict(c.execute('SELECT * FROM browser_profiles WHERE profile_id=?', (profile_id,)).fetchone())
    else:
        enrolled_ts = stamp(data.get('enrolled_at') or data.get('time') or received)
        c.execute(
            'INSERT INTO browser_profiles(profile_id,collector_id,device_id,user_sid,account,browser_name,browser_version,'
            'extension_id,extension_version,profile_label,enrollment_state,paused_at,enrolled_at,last_seen_at,last_delivery_at,'
            'native_host_version,dropped_count,queue_depth,last_error,diagnostics) '
            'VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
            (profile_id, collector['id'], did, sid, acct, browser_name, data.get('browser_version'),
             ext_id, data.get('extension_version'), data.get('profile_label') or f"{browser_name} Lab Profile",
             'Enrolled', None, enrolled_ts, received, received, data.get('native_host_version') or '1.0.0',
             int(data.get('dropped_count') or 0), int(data.get('queue_depth') or 0), None, js(data.get('diagnostics') or {}))
        )
        return dict(c.execute('SELECT * FROM browser_profiles WHERE profile_id=?', (profile_id,)).fetchone())

def ingest_browser_enrollment(c, payload: dict, collector: dict, received: str):
    data = payload.get('data') or {}
    _verify_browser_profile_context(c, data, collector, received)

def ingest_browser_status(c, payload: dict, collector: dict, received: str):
    data = payload.get('data') or {}
    prof = _verify_browser_profile_context(c, data, collector, received)
    when = stamp(data.get('time') or payload.get('time') or received)
    raw_state = str(data.get('enrollment_state') or data.get('state') or '').strip().casefold()
    state = 'Paused' if raw_state in ('paused', 'pause') else ('Enrolled' if raw_state in ('enrolled', 'active', 'resumed', 'resume') else (data.get('enrollment_state') or data.get('state')))
    gap_kind = data.get('gap_kind')

    if state == 'Paused' and prof['enrollment_state'] != 'Paused':
        c.execute("UPDATE browser_profiles SET enrollment_state='Paused', paused_at=? WHERE profile_id=?", (when, prof['profile_id']))
        c.execute(
            'INSERT INTO browser_collection_gaps(id,profile_id,device_id,user_sid,gap_kind,started_at,ended_at,details) VALUES(?,?,?,?,?,?,?,?)',
            (uid(), prof['profile_id'], prof['device_id'], prof['user_sid'], 'User paused', when, None, js({'reason': 'User paused collection from extension popup'}))
        )
    elif state == 'Enrolled' and prof['enrollment_state'] == 'Paused':
        c.execute("UPDATE browser_profiles SET enrollment_state='Enrolled', paused_at=NULL WHERE profile_id=?", (prof['profile_id'],))
        open_gap = c.execute(
            "SELECT id FROM browser_collection_gaps WHERE profile_id=? AND ended_at IS NULL ORDER BY started_at DESC LIMIT 1",
            (prof['profile_id'],)
        ).fetchone()
        if open_gap:
            c.execute('UPDATE browser_collection_gaps SET ended_at=? WHERE id=?', (when, open_gap['id']))
    elif gap_kind in ('Service worker restart', 'Native host disconnected', 'Queue overflow drop'):
        c.execute(
            'INSERT INTO browser_collection_gaps(id,profile_id,device_id,user_sid,gap_kind,started_at,ended_at,details) VALUES(?,?,?,?,?,?,?,?)',
            (uid(), prof['profile_id'], prof['device_id'], prof['user_sid'], gap_kind,
             stamp(data.get('started_at') or when), stamp(data['ended_at']) if data.get('ended_at') else when,
             js(data.get('details') or {}))
        )

def ingest_browser_navigation(c, payload: dict, collector: dict, received: str, policy: dict):
    data = payload.get('data') or {}
    if data.get('incognito') is True or data.get('private_mode') is True:
        raise ValueError('Private/incognito browsing records are rejected by privacy policy')
    frame_id = int(data.get('frame_id') or 0)
    if frame_id != 0:
        raise ValueError('Only top-level frame (frame_id=0) navigations are recorded; iframe loads are excluded')

    prof = _verify_browser_profile_context(c, data, collector, received)
    if prof['enrollment_state'] == 'Paused':
        raise ValueError('Browser profile is currently paused; navigation rejected')

    raw_input = data.get('normalized_domain') or data.get('domain') or data.get('url')
    domain, scheme, port = sanitize_domain_only(raw_input)
    if not domain or not scheme:
        raise ValueError('Navigation rejected: only valid HTTP/HTTPS domains are permitted')
    if data.get('scheme') and str(data['scheme']).casefold() in ('http', 'https'):
        scheme = str(data['scheme']).casefold()

    nav_time = stamp(data.get('navigation_time') or data.get('time') or payload.get('time') or received)
    if dt(nav_time) < dt(prof['enrolled_at']) - timedelta(seconds=60):
        raise ValueError('Pre-enrollment browser history import is prohibited')

    transition_type = str(data.get('transition_type') or 'link').strip().casefold()
    qualifiers = data.get('transition_qualifiers') if isinstance(data.get('transition_qualifiers'), list) else []
    qualifiers = [str(q).strip() for q in qualifiers[:10]]

    if transition_type in ('reload', 'auto_subframe') or 'restore' in transition_type or any('restore' in q.casefold() for q in qualifiers):
        visit_kind = 'Tab reload / restore'
    elif any('redirect' in q.casefold() for q in qualifiers):
        visit_kind = 'Redirected top-level navigation'
    else:
        visit_kind = 'Top-level navigation'

    tab_id = int(data['tab_id']) if data.get('tab_id') is not None else None
    # Deduplicate same-profile, same-tab, same-domain callbacks within a 2-second bucket
    bucket_2s = int(dt(nav_time).timestamp() // 2)
    ident_key = digest(js([prof['profile_id'], domain, scheme, tab_id, transition_type, bucket_2s]))

    if c.execute('SELECT 1 FROM browser_navigations WHERE identity_key=?', (ident_key,)).fetchone():
        return

    sanitized_evidence = {
        'profile_id': prof['profile_id'],
        'normalized_domain': domain,
        'scheme': scheme,
        'port': port,
        'navigation_time': nav_time,
        'transition_type': transition_type,
        'transition_qualifiers': qualifiers,
        'visit_kind': visit_kind,
        'tab_id': tab_id,
        'frame_id': 0,
        'privacy_note': 'URL path, query string, fragment, credentials, and page title stripped prior to persistence.'
    }
    nav_id = str(payload.get('id') or uid())
    c.execute(
        'INSERT INTO browser_navigations(id,identity_key,profile_id,collector_id,device_id,user_sid,account,browser_name,'
        'navigation_time,received_at,normalized_domain,scheme,port,transition_type,transition_qualifiers,visit_kind,'
        'tab_id,frame_id,sanitization_verified,raw_sanitized_evidence) '
        'VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,?)',
        (nav_id, ident_key, prof['profile_id'], collector['id'], prof['device_id'], prof['user_sid'], prof['account'],
         prof['browser_name'], nav_time, received, domain, scheme, port, transition_type, js(qualifiers),
         visit_kind, tab_id, 0, js(sanitized_evidence))
    )

    # Check if this navigation correlates with a recent download or restricted domain policy
    correlate_navigation(c, {
        'id': nav_id, 'profile_id': prof['profile_id'], 'device_id': prof['device_id'],
        'user_sid': prof['user_sid'], 'account': prof['account'], 'normalized_domain': domain,
        'navigation_time': nav_time
    })
    evaluate_domain_policy_rule(c, prof, domain, nav_time, nav_id, policy)
    c.execute('UPDATE devices SET last_event=MAX(COALESCE(last_event,?),?) WHERE id=?', (nav_time, nav_time, prof['device_id']))
    c.execute('UPDATE collectors SET last_event=MAX(COALESCE(last_event,?),?) WHERE id=?', (nav_time, nav_time, collector['id']))

def _validate_download_hash_state(final_path: str | None, sha256: str | None, hash_state_hint: str | None) -> tuple[str | None, str]:
    if not final_path:
        return None, 'Not collected'
    norm = final_path.replace('/', '\\')
    if '..' in norm.split('\\'):
        return None, 'Disallowed path'
    low = norm.casefold()
    approved = ('\\downloads\\', 'c:\\admonitor-scratch\\', 'c:\\admonitor-demo\\')
    if not (any(a in low for a in approved) or low.startswith('downloads\\')):
        return None, 'Disallowed path'
    if hash_state_hint in ('File changed before hashing', 'File missing', 'Size limit exceeded', 'Disallowed path', 'Not collected'):
        return None, hash_state_hint
    if sha256 and re.fullmatch(r'[0-9a-fA-F]{64}', str(sha256).strip()):
        return str(sha256).strip().lower(), 'Verified'
    return None, (hash_state_hint or 'Not collected')

def ingest_browser_download(c, payload: dict, collector: dict, received: str, policy: dict):
    data = payload.get('data') or {}
    if data.get('incognito') is True or data.get('private_mode') is True:
        raise ValueError('Private/incognito download records are rejected by privacy policy')
    prof = _verify_browser_profile_context(c, data, collector, received)
    dl_raw_id = data.get('browser_download_id') if data.get('browser_download_id') is not None else data.get('download_id')
    if dl_raw_id is None:
        raise ValueError('browser_download_id is required')
    dl_num = int(dl_raw_id)
    dl_id = digest(f"dl:{prof['profile_id']}:{dl_num}")

    started_at = stamp(data.get('started_at') or data.get('start_time') or data.get('time') or payload.get('time') or received)
    updated_at = stamp(data.get('updated_at') or data.get('end_time') or data.get('time') or received)
    state = str(data.get('state') or 'in_progress').strip().casefold()
    if state == 'complete':
        state = 'completed'
    if state not in ('in_progress', 'completed', 'interrupted', 'canceled', 'unknown'):
        state = 'unknown'
    completed_at = stamp(data.get('completed_at') or data.get('end_time')) if (data.get('completed_at') or data.get('end_time')) else (updated_at if state == 'completed' else None)

    final_path = str(data.get('final_path') or data.get('target_path') or data.get('filename') or '').strip() or None
    filename = str(data.get('filename') or '').strip()
    if final_path:
        filename = ntpath.basename(final_path)
    elif filename:
        filename = ntpath.basename(filename)
    else:
        filename = None

    canon_path = canonical(final_path, policy.get('path_mappings', ())) if final_path else None
    ext = posixpath.splitext(filename)[1].casefold() if filename and '.' in filename else None

    src_domain, _, _ = sanitize_domain_only(data.get('source_domain') or data.get('url') or data.get('final_url'))
    fin_domain, _, _ = sanitize_domain_only(data.get('final_domain') or data.get('final_url') or data.get('url'))
    ref_domain, _, _ = sanitize_domain_only(data.get('referrer_domain') or data.get('referrer'))

    def clean_bytes(val):
        if val is None:
            return None
        iv = int(val)
        return iv if iv >= 0 else None

    bytes_rec = clean_bytes(data.get('bytes_received'))
    total_b = clean_bytes(data.get('total_bytes'))
    final_b = clean_bytes(data.get('final_size_bytes'))
    if state == 'completed' and final_b is None:
        final_b = bytes_rec if bytes_rec is not None else total_b

    danger = str(data.get('danger_type') or '').strip() or None
    mime = str(data.get('mime_type') or '').strip() or None
    interrupt_reason = str(data.get('interrupt_reason') or '').strip() or None
    if state == 'interrupted' and interrupt_reason and 'canceled' in interrupt_reason.casefold():
        state = 'canceled'
    exists_disk = (1 if data['exists_on_disk'] else 0) if data.get('exists_on_disk') is not None else None

    sha256, hash_state = _validate_download_hash_state(final_path, data.get('sha256'), data.get('hash_state'))

    sanitized_ev = {
        'profile_id': prof['profile_id'],
        'browser_download_id': dl_num,
        'filename': filename,
        'final_path': final_path,
        'source_domain': src_domain,
        'final_domain': fin_domain,
        'referrer_domain': ref_domain,
        'mime_type': mime,
        'bytes_received': bytes_rec,
        'total_bytes': total_b,
        'final_size_bytes': final_b,
        'state': state,
        'interrupt_reason': interrupt_reason,
        'browser_danger_assessment': danger,
        'sha256': sha256,
        'hash_state': hash_state,
        'privacy_note': 'Signed URL query strings and credentials stripped before persistence.'
    }

    existing = c.execute('SELECT * FROM browser_downloads WHERE id=?', (dl_id,)).fetchone()
    if not existing:
        c.execute(
            'INSERT INTO browser_downloads(id,profile_id,collector_id,device_id,user_sid,account,browser_name,browser_download_id,'
            'started_at,completed_at,updated_at,received_at,filename,final_path,canonical_path,source_domain,final_domain,'
            'referrer_domain,mime_type,file_extension,bytes_received,total_bytes,final_size_bytes,state,interrupt_reason,'
            'danger_type,exists_on_disk,sha256,hash_state,raw_sanitized_evidence) '
            'VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
            (dl_id, prof['profile_id'], collector['id'], prof['device_id'], prof['user_sid'], prof['account'],
             prof['browser_name'], dl_num, started_at, completed_at, updated_at, received, filename, final_path,
             canon_path, src_domain, fin_domain, ref_domain, mime, ext, bytes_rec, total_b, final_b, state,
             interrupt_reason, danger, exists_disk, sha256, hash_state, js(sanitized_ev))
        )
    else:
        # Preserve completed state if an out-of-order in_progress packet arrives late
        merged_state = 'completed' if existing['state'] == 'completed' and state == 'in_progress' else state
        c.execute(
            'UPDATE browser_downloads SET completed_at=COALESCE(?,completed_at), updated_at=MAX(updated_at,?), received_at=MAX(received_at,?), '
            'filename=COALESCE(?,filename), final_path=COALESCE(?,final_path), canonical_path=COALESCE(?,canonical_path), '
            'source_domain=COALESCE(?,source_domain), final_domain=COALESCE(?,final_domain), referrer_domain=COALESCE(?,referrer_domain), '
            'mime_type=COALESCE(?,mime_type), file_extension=COALESCE(?,file_extension), bytes_received=COALESCE(?,bytes_received), '
            'total_bytes=COALESCE(?,total_bytes), final_size_bytes=COALESCE(?,final_size_bytes), state=?, '
            'interrupt_reason=COALESCE(?,interrupt_reason), danger_type=COALESCE(?,danger_type), '
            'exists_on_disk=COALESCE(?,exists_on_disk), sha256=COALESCE(?,sha256), '
            'hash_state=CASE WHEN ?!="Not collected" THEN ? ELSE hash_state END, raw_sanitized_evidence=? WHERE id=?',
            (completed_at, updated_at, received, filename, final_path, canon_path, src_domain, fin_domain, ref_domain,
             mime, ext, bytes_rec, total_b, final_b, merged_state, interrupt_reason, danger, exists_disk,
             sha256, hash_state, hash_state, js(sanitized_ev), dl_id)
        )

    # Record state revision without double-counting download rows
    rev_id = digest(js([dl_id, state, filename, final_path, bytes_rec if state != 'in_progress' else 'progress']))
    c.execute(
        'INSERT OR REPLACE INTO browser_download_revisions(id,download_id,observed_at,received_at,state,filename,final_path,'
        'bytes_received,total_bytes,danger_type,details) VALUES(?,?,?,?,?,?,?,?,?,?,?)',
        (rev_id, dl_id, updated_at, received, state, filename, final_path, bytes_rec, total_b, danger, js(sanitized_ev))
    )

    dl_row = dict(c.execute('SELECT * FROM browser_downloads WHERE id=?', (dl_id,)).fetchone())
    correlate_download(c, dl_row, policy)
    if dl_row['state'] == 'completed':
        evaluate_download_rules(c, dl_row, collector, received, policy)

    c.execute('UPDATE devices SET last_event=MAX(COALESCE(last_event,?),?) WHERE id=?', (updated_at, updated_at, prof['device_id']))
    c.execute('UPDATE collectors SET last_event=MAX(COALESCE(last_event,?),?) WHERE id=?', (updated_at, updated_at, collector['id']))

def _upsert_correlation_link(c, link: dict):
    existing = c.execute('SELECT id, review_status, reviewed_by, reviewed_at FROM correlation_links WHERE id=?', (link['id'],)).fetchone()
    if existing:
        c.execute(
            'UPDATE correlation_links SET updated_at=?, time_delta_seconds=?, confidence=?, relationship_label=?, '
            'matched_fields=?, missing_fields=?, competing_candidates=?, what_is_established=?, what_is_not_established=?, '
            'justification=? WHERE id=?',
            (now(), link['time_delta_seconds'], link['confidence'], link['relationship_label'],
             js(link['matched_fields']), js(link['missing_fields']), js(link['competing_candidates']),
             link['what_is_established'], link['what_is_not_established'], link['justification'], link['id'])
        )
    else:
        c.execute(
            'INSERT INTO correlation_links(id,case_key,device_id,user_sid,account,link_kind,source_type,source_id,'
            'target_type,target_id,created_at,updated_at,event_time,time_delta_seconds,rule_id,rule_version,confidence,'
            'relationship_label,matched_fields,missing_fields,competing_candidates,what_is_established,what_is_not_established,'
            'justification,review_status,reviewed_by,reviewed_at) '
            'VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
            (link['id'], link['case_key'], link['device_id'], link.get('user_sid'), link.get('account'),
             link['link_kind'], link['source_type'], link['source_id'], link['target_type'], link['target_id'],
             now(), now(), link['event_time'], link['time_delta_seconds'], link['rule_id'], link.get('rule_version', 1),
             link['confidence'], link['relationship_label'], js(link['matched_fields']), js(link['missing_fields']),
             js(link['competing_candidates']), link['what_is_established'], link['what_is_not_established'],
             link['justification'], 'Needs review', None, None)
        )

def correlate_navigation(c, nav: dict):
    """When a navigation arrives (including late arrival), check if any download on the same profile started shortly after."""
    start_w = nav['navigation_time']
    end_w = stamp(dt(nav['navigation_time']) + timedelta(seconds=300))
    downloads = c.execute(
        'SELECT * FROM browser_downloads WHERE profile_id=? AND started_at>=? AND started_at<=?',
        (nav['profile_id'], start_w, end_w)
    ).fetchall()
    for dl in downloads:
        correlate_download(c, dict(dl), settings(c))

def correlate_download(c, dl: dict, policy: dict):
    """Links a browser download to preceding same-profile navigations and any subsequent process executions."""
    case_key = f"dl_case:{dl['id']}"
    # 1. Navigation -> Download correlation
    win_start = stamp(dt(dl['started_at']) - timedelta(seconds=300))
    win_end = stamp(dt(dl['started_at']) + timedelta(seconds=5))
    navs = c.execute(
        'SELECT * FROM browser_navigations WHERE profile_id=? AND navigation_time>=? AND navigation_time<=? ORDER BY navigation_time DESC',
        (dl['profile_id'], win_start, win_end)
    ).fetchall()

    dl_domains = {d for d in (dl.get('source_domain'), dl.get('final_domain'), dl.get('referrer_domain')) if d}
    matching_nav = None
    competing = []
    for n in navs:
        if n['normalized_domain'] in dl_domains and not matching_nav:
            matching_nav = n
        else:
            competing.append({'id': n['id'], 'domain': n['normalized_domain'], 'time': n['navigation_time']})

    if matching_nav:
        delta = round((dt(dl['started_at']) - dt(matching_nav['navigation_time'])).total_seconds(), 2)
        matched = ['profile_id', 'device_id', 'user_sid', 'domain']
        if dl.get('referrer_domain') == matching_nav['normalized_domain']:
            matched.append('referrer_domain')
        missing = [] if dl.get('referrer_domain') else ['referrer_domain']
        conf = 'High' if dl.get('referrer_domain') == matching_nav['normalized_domain'] and not competing else ('Medium' if not competing else 'Low')
        link_id = digest(f"nav_dl:{matching_nav['id']}:{dl['id']}")
        _upsert_correlation_link(c, {
            'id': link_id,
            'case_key': case_key,
            'device_id': dl['device_id'],
            'user_sid': dl['user_sid'],
            'account': dl['account'],
            'link_kind': 'navigation_to_download',
            'source_type': 'browser_navigation',
            'source_id': matching_nav['id'],
            'target_type': 'browser_download',
            'target_id': dl['id'],
            'event_time': dl['started_at'],
            'time_delta_seconds': delta,
            'rule_id': 'corr_nav_download',
            'rule_version': 1,
            'confidence': conf,
            'relationship_label': 'Same-profile domain visit preceding download',
            'matched_fields': matched,
            'missing_fields': missing,
            'competing_candidates': competing[:5],
            'what_is_established': f"Enrolled profile visited {matching_nav['normalized_domain']} {delta}s before downloading {dl.get('filename') or 'file'} from the same domain.",
            'what_is_not_established': 'Browser tab focus, user intent, or whether the download was triggered by a user click versus an automatic page redirect.',
            'justification': f"Same enrolled browser profile ({dl['profile_id'][:10]}), Windows SID ({dl['user_sid']}), and matching hostname ({matching_nav['normalized_domain']})."
        })

    # 2. Check if any process instance already started after this download
    if dl['state'] == 'completed':
        t_anchor = dl.get('completed_at') or dl['started_at']
        t_limit = stamp(dt(t_anchor) + timedelta(seconds=3600))
        procs = c.execute(
            'SELECT * FROM process_instances WHERE device_id=? AND first_seen_at>=? AND first_seen_at<=?',
            (dl['device_id'], stamp(dt(t_anchor) - timedelta(seconds=2)), t_limit)
        ).fetchall()
        for p in procs:
            _correlate_download_and_process(c, dl, dict(p), policy)

def correlate_process_instance(c, proc: dict, policy: dict):
    """Links a process instance to any preceding completed download on the same device and compatible user, plus verified parent lineage."""
    t_proc = proc.get('creation_time') or proc['first_seen_at']
    win_start = stamp(dt(t_proc) - timedelta(seconds=3600))
    win_end = stamp(dt(t_proc) + timedelta(seconds=5))
    downloads = c.execute(
        "SELECT * FROM browser_downloads WHERE device_id=? AND state='completed' AND COALESCE(completed_at,started_at)>=? AND COALESCE(completed_at,started_at)<=? ORDER BY COALESCE(completed_at,started_at) DESC",
        (proc['device_id'], win_start, win_end)
    ).fetchall()
    for dl in downloads:
        _correlate_download_and_process(c, dict(dl), proc, policy)

def _correlate_download_and_process(c, dl: dict, proc: dict, policy: dict):
    # Must be same device
    if dl['device_id'] != proc['device_id']:
        return
    # Must be compatible user SID (if proc has user_sid, it must match dl.user_sid)
    if proc.get('user_sid') and dl.get('user_sid') and proc['user_sid'] != dl['user_sid']:
        return

    dl_time = dl.get('completed_at') or dl['started_at']
    proc_time = proc.get('creation_time') or proc['first_seen_at']
    delta = round((dt(proc_time) - dt(dl_time)).total_seconds(), 2)
    if delta < -2.0:
        return

    case_key = f"dl_case:{dl['id']}"
    dl_canon = dl.get('canonical_path') or (canonical(dl['final_path']) if dl.get('final_path') else None)
    dl_base = (dl.get('filename') or '').casefold()
    dl_tail = (dl.get('final_path') or '').replace('/', '\\').casefold()
    if '\\downloads\\' in dl_tail:
        dl_tail = 'downloads\\' + dl_tail.split('\\downloads\\', 1)[1]

    # Case A: Direct executable launch (process image path matches downloaded path)
    proc_canon = proc.get('canonical_path') or (canonical(proc['executable_path']) if proc.get('executable_path') else None)
    if dl_canon and proc_canon and dl_canon == proc_canon and proc['name'].casefold() not in INTERPRETER_NAMES:
        matched = ['device_id', 'user_sid', 'canonical_path']
        missing = []
        if dl.get('sha256') and proc.get('sha256'):
            if dl['sha256'] == proc['sha256']:
                matched.append('sha256')
                conf = 'High'
                label = 'Executable launch observed'
                established = f"Downloaded executable {dl.get('filename')} was launched as PID {proc['pid']} with matching SHA-256 content hash."
            else:
                conf = 'Low'
                label = 'Possible related activity'
                missing.append('matching_sha256 (file hash changed after download)')
                established = f"An executable at the downloaded path ({dl.get('final_path')}) was launched, but its SHA-256 hash differs from the downloaded file."
        else:
            conf = 'Medium'
            label = 'Executable launch observed'
            missing.append('sha256')
            established = f"Downloaded executable path ({dl.get('final_path')}) matches launched process image ({proc['name']}, PID {proc['pid']})."

        link_id = digest(f"dl_exe:{dl['id']}:{proc['instance_key']}")
        _upsert_correlation_link(c, {
            'id': link_id,
            'case_key': case_key,
            'device_id': dl['device_id'],
            'user_sid': dl['user_sid'],
            'account': dl['account'],
            'link_kind': 'download_to_executable_launch',
            'source_type': 'browser_download',
            'source_id': dl['id'],
            'target_type': 'process_instance',
            'target_id': proc['instance_key'],
            'event_time': proc_time,
            'time_delta_seconds': delta,
            'rule_id': 'download_execute',
            'rule_version': 1,
            'confidence': conf,
            'relationship_label': label,
            'matched_fields': matched,
            'missing_fields': missing,
            'competing_candidates': [],
            'what_is_established': established,
            'what_is_not_established': 'Malicious intent, runtime payload behavior, or network/file effects after process start.',
            'justification': f"Same enrolled device ({dl['device_id'][:8]}), user SID ({dl['user_sid']}), and exact canonical executable path ({dl_canon}) {delta}s after download completion."
        })
        _record_verified_parent_link(c, case_key, proc)
        _emit_correlated_download_execute_alert(c, dl, proc, label, established, policy)
        return

    # Case B: Downloaded script referenced in interpreter command line
    if proc.get('command_line'):
        refs = extract_referenced_script_paths(proc['command_line'])
        for ref in refs:
            exact_canon_match = bool(dl_canon and ref.get('canonical_path') and dl_canon == ref['canonical_path'])
            tail_match = bool(
                not exact_canon_match
                and dl_tail
                and ref.get('relative_tail')
                and (dl_tail.endswith('\\' + ref['relative_tail']) or dl_tail == ref['relative_tail'])
            )
            basename_only_match = bool(
                not exact_canon_match and not tail_match and dl_base and ref.get('basename') == dl_base
            )
            if not (exact_canon_match or tail_match or basename_only_match):
                continue

            matched = ['device_id', 'user_sid']
            missing = []
            if not (dl.get('sha256') and proc.get('sha256')):
                missing.append('sha256')

            if exact_canon_match and not ref.get('ambiguous_quoting'):
                matched.extend(['canonical_path', 'script_argument'])
                conf = 'High' if 'sha256' not in missing else 'Medium'
                label = 'Downloaded path referenced by process command line'
                established = f"A downloaded script path ({dl.get('final_path')}) was subsequently referenced in a {proc['name']} command (PID {proc['pid']})."
            elif tail_match and not ref.get('ambiguous_quoting'):
                matched.extend(['relative_downloads_path', 'script_argument'])
                missing.append('working_directory')
                conf = 'Medium'
                label = 'Downloaded path referenced by process command line'
                established = f"A downloaded script path ({dl.get('final_path')}) was subsequently referenced as '{ref['raw_path']}' in a {proc['name']} command (PID {proc['pid']})."
            else:
                matched.append('script_basename')
                missing.extend(['working_directory', 'full_script_path'])
                if ref.get('ambiguous_quoting'):
                    missing.append('unquoted_path_disambiguation')
                conf = 'Low'
                label = 'Possible related activity'
                established = f"Process {proc['name']} (PID {proc['pid']}) referenced '{ref['raw_path']}', which shares a filename with downloaded file {dl.get('filename')}, but the full path or working directory is unverified."

            # Check competing downloads of the same filename on the same device
            comp_rows = c.execute(
                "SELECT id, filename, final_path, completed_at FROM browser_downloads WHERE device_id=? AND id!=? AND lower(filename)=lower(?)",
                (dl['device_id'], dl['id'], dl.get('filename') or '')
            ).fetchall()
            competing = [{'id': r['id'], 'path': r['final_path'], 'completed_at': r['completed_at']} for r in comp_rows]
            if competing and conf == 'High':
                conf = 'Medium'

            link_id = digest(f"dl_script:{dl['id']}:{proc['instance_key']}")
            _upsert_correlation_link(c, {
                'id': link_id,
                'case_key': case_key,
                'device_id': dl['device_id'],
                'user_sid': dl['user_sid'],
                'account': dl['account'],
                'link_kind': 'download_to_script_invocation',
                'source_type': 'browser_download',
                'source_id': dl['id'],
                'target_type': 'process_instance',
                'target_id': proc['instance_key'],
                'event_time': proc_time,
                'time_delta_seconds': delta,
                'rule_id': 'download_execute',
                'rule_version': 1,
                'confidence': conf,
                'relationship_label': label,
                'matched_fields': matched,
                'missing_fields': missing,
                'competing_candidates': competing[:5],
                'what_is_established': established,
                'what_is_not_established': 'Malicious intent or harmful effects. A command-line reference does not prove the script completed successfully, performed harmful actions, or caused a data leak.',
                'justification': f"Same enrolled endpoint ({dl['device_id'][:8]}) and Windows SID ({dl['user_sid']}); download completed {delta}s before {proc['name']} (PID {proc['pid']}) started with argument '{ref['raw_path']}'."
            })
            _record_verified_parent_link(c, case_key, proc)
            if conf in ('High', 'Medium'):
                _emit_correlated_download_execute_alert(c, dl, proc, label, established, policy)
            return

def _record_verified_parent_link(c, case_key: str, proc: dict):
    if not proc.get('parent_instance_key'):
        return
    parent = row(c.execute('SELECT * FROM process_instances WHERE instance_key=?', (proc['parent_instance_key'],)).fetchone())
    if not parent:
        return
    # Never infer the browser is the parent unless actual OS creation records verify it
    link_id = digest(f"lineage:{case_key}:{parent['instance_key']}:{proc['instance_key']}")
    proc_time = proc.get('creation_time') or proc['first_seen_at']
    parent_time = parent.get('creation_time') or parent['first_seen_at']
    delta = round((dt(proc_time) - dt(parent_time)).total_seconds(), 2)
    _upsert_correlation_link(c, {
        'id': link_id,
        'case_key': case_key,
        'device_id': proc['device_id'],
        'user_sid': proc.get('user_sid'),
        'account': proc.get('account'),
        'link_kind': 'process_lineage',
        'source_type': 'process_instance',
        'source_id': parent['instance_key'],
        'target_type': 'process_instance',
        'target_id': proc['instance_key'],
        'event_time': proc_time,
        'time_delta_seconds': delta,
        'rule_id': 'process_lineage',
        'rule_version': 1,
        'confidence': 'High' if 'Strong' in proc['parent_confidence'] else 'Medium',
        'relationship_label': 'Verified parent-child process lineage',
        'matched_fields': ['device_id', 'parent_pid', 'creation_time_order'],
        'missing_fields': [] if 'Strong' in proc['parent_confidence'] else ['parent_process_guid'],
        'competing_candidates': [],
        'what_is_established': f"Parent process {parent['name']} (PID {parent['pid']}) was verified active before child process {proc['name']} (PID {proc['pid']}) was created.",
        'what_is_not_established': 'Parent-child process creation does not establish whether the action was user-interactive or automated.',
        'justification': f"Lineage confidence: {proc['parent_confidence']}."
    })

def _device_hostname(c, device_id: str | None) -> str:
    if not device_id:
        return 'unknown-endpoint'
    row = c.execute('SELECT hostname FROM devices WHERE id=?', (device_id,)).fetchone()
    return row['hostname'] if row and row['hostname'] else device_id

def _emit_correlated_download_execute_alert(c, dl: dict, proc: dict, label: str, established: str, policy: dict):
    from .rules import emit
    rule = c.execute("SELECT * FROM rules WHERE id='download_execute' AND enabled=1").fetchone()
    if not rule:
        return
    proc_time = proc.get('creation_time') or proc['first_seen_at']
    ev_id = digest(f"corr_ev:{dl['id']}:{proc['instance_key']}")
    host = _device_hostname(c, dl['device_id'])
    c.execute(
        'INSERT OR IGNORE INTO events(id,identity,time,received_at,event_id,provider,channel,source_computer,collector_id,'
        'source_record,user_sid,account,logon_id,device_id,access_device_id,attribution,category,result,object_path,canonical_path,'
        'source_address,process_id,process_guid,parent_id,process_path,command_line,fields,raw,evidence_type,late_seconds,rules_done) '
        'VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1)',
        (ev_id, ev_id, proc_time, now(), None, 'ADMonitor.CorrelationEngine', 'ADMonitor',
         host, dl['collector_id'], ev_id, dl['user_sid'], dl['account'], None, dl['device_id'], dl['device_id'],
         'Strong: same enrolled device and Windows SID', 'script_block', 'observed', dl.get('final_path'),
         dl.get('canonical_path'), None, str(proc['pid']), proc.get('process_guid'),
         str(proc['parent_pid']) if proc.get('parent_pid') else None, proc.get('executable_path') or proc['name'],
         proc.get('command_line'), js({'download_id': dl['id'], 'process_instance_key': proc['instance_key'], 'relationship': label}),
         js({'download': dl['id'], 'process': proc['instance_key']}), 'correlated_evidence', 0.0)
    )
    ev_row = dict(c.execute('SELECT * FROM events WHERE id=?', (ev_id,)).fetchone())
    detail = f"{label}: {established} Time/path correlation does not establish malicious intent."
    emit(c, rule, ev_row, [ev_row], detail, 1, policy)

def evaluate_process_resource_rule(c, proc: dict, policy: dict):
    """Sustained process resource usage across multiple real samples -> resource/performance finding, NOT malware."""
    rule = c.execute("SELECT * FROM rules WHERE id='sustained_resource' AND enabled=1").fetchone()
    if not rule:
        return
    cfg = obj(rule['config'])
    threshold_cpu = float(cfg.get('threshold') or 80)
    samples = c.execute(
        'SELECT * FROM process_samples WHERE instance_key=? AND cpu_percent IS NOT NULL ORDER BY sampled_at DESC LIMIT 3',
        (proc['instance_key'],)
    ).fetchall()
    col = c.execute("SELECT id, expected_host FROM collectors WHERE device_id=? LIMIT 1", (proc['device_id'],)).fetchone()
    if not col:
        return
    if len(samples) >= 3 and all(float(s['cpu_percent']) >= threshold_cpu for s in samples):
        from .rules import emit
        avg_cpu = round(sum(float(s['cpu_percent']) for s in samples) / len(samples), 1)
        ev_id = digest(f"res_ev2:{proc['instance_key']}:{samples[0]['sampled_at'][:16]}")
        host = col['expected_host'] or _device_hostname(c, proc['device_id'])
        c.execute(
            'INSERT OR IGNORE INTO events(id,identity,time,received_at,event_id,provider,channel,source_computer,collector_id,'
            'source_record,user_sid,account,logon_id,device_id,access_device_id,attribution,category,result,object_path,canonical_path,'
            'source_address,process_id,process_guid,parent_id,process_path,command_line,fields,raw,evidence_type,late_seconds,rules_done) '
            'VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1)',
            (ev_id, ev_id, samples[0]['sampled_at'], now(), None, 'ADMonitor.ProcessMonitor', 'ADMonitor',
             host, col['id'], ev_id, proc.get('user_sid'), proc.get('account'), None,
             proc['device_id'], proc['device_id'], 'Strong: endpoint process snapshot', 'process_resource', 'observed',
             proc.get('executable_path'), proc.get('canonical_path'), None, str(proc['pid']), proc.get('process_guid'),
             None, proc.get('executable_path') or proc['name'], proc.get('command_line'),
             js({'avg_cpu_percent': avg_cpu, 'consecutive_samples': len(samples)}), js({'instance_key': proc['instance_key']}),
             'process_snapshot', 0.0)
        )
        ev_row = dict(c.execute('SELECT * FROM events WHERE id=?', (ev_id,)).fetchone())
        detail = (
            f"Resource/performance review finding (not a malware diagnosis): {proc['name']} (PID {proc['pid']}) "
            f"averaged {avg_cpu}% normalized CPU across {len(samples)} consecutive samples."
        )
        emit(c, rule, ev_row, [ev_row], detail, int(avg_cpu), policy)

def evaluate_download_rules(c, dl: dict, collector: dict, received: str, policy: dict):
    """Evaluates script/executable download policy review and completed-download volume threshold without double-counting."""
    from .rules import emit
    host = collector.get('expected_host') or _device_hostname(c, dl['device_id'])
    # 1. Script / executable download review rule
    ext = (dl.get('file_extension') or '').casefold()
    if ext in SCRIPT_EXTENSIONS + EXECUTABLE_EXTENSIONS:
        rule = c.execute("SELECT * FROM rules WHERE id='script_download_review' AND enabled=1").fetchone()
        if rule:
            ev_id = digest(f"dl_rev_ev:{dl['id']}")
            c.execute(
                'INSERT OR IGNORE INTO events(id,identity,time,received_at,event_id,provider,channel,source_computer,collector_id,'
                'source_record,user_sid,account,logon_id,device_id,access_device_id,attribution,category,result,object_path,canonical_path,'
                'source_address,process_id,process_guid,parent_id,process_path,command_line,fields,raw,evidence_type,late_seconds,rules_done) '
                'VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1)',
                (ev_id, ev_id, dl.get('completed_at') or dl['started_at'], received, None, 'ADMonitor.BrowserExtension', 'ADMonitor',
                 host, collector['id'], ev_id, dl['user_sid'], dl['account'], None,
                 dl['device_id'], dl['device_id'], 'Strong: enrolled browser profile + OS SID', 'download', 'observed',
                 dl.get('final_path'), dl.get('canonical_path'), None, None, None, None, dl.get('browser_name'), None,
                 js({'filename': dl.get('filename'), 'source_domain': dl.get('source_domain'), 'bytes': dl.get('final_size_bytes')}),
                 dl['raw_sanitized_evidence'], 'browser_download', 0.0)
            )
            ev_row = dict(c.execute('SELECT * FROM events WHERE id=?', (ev_id,)).fetchone())
            detail = (
                f"Policy review event: completed download of script/executable '{dl.get('filename')}' from "
                f"{dl.get('source_domain') or 'unknown domain'}. File extension alone does not establish malicious content."
            )
            emit(c, rule, ev_row, [ev_row], detail, 1, policy)

    # 2. Completed download volume threshold (counts completed downloads once by final_size_bytes)
    vol_rule = c.execute("SELECT * FROM rules WHERE id='downloads' AND enabled=1").fetchone()
    if vol_rule:
        cfg = obj(vol_rule['config'])
        t_end = dl.get('completed_at') or dl['started_at']
        t_start = stamp(dt(t_end) - timedelta(seconds=cfg['window_seconds']))
        completed_dls = c.execute(
            "SELECT id, filename, final_size_bytes, completed_at FROM browser_downloads "
            "WHERE user_sid=? AND state='completed' AND COALESCE(completed_at,started_at)>=? AND COALESCE(completed_at,started_at)<=?",
            (dl['user_sid'], t_start, t_end)
        ).fetchall()
        total_bytes = sum(int(r['final_size_bytes'] or 0) for r in completed_dls)
        if total_bytes >= int(cfg['threshold']):
            ev_id = digest(f"dl_vol_ev:{dl['id']}")
            c.execute(
                'INSERT OR IGNORE INTO events(id,identity,time,received_at,event_id,provider,channel,source_computer,collector_id,'
                'source_record,user_sid,account,logon_id,device_id,access_device_id,attribution,category,result,object_path,canonical_path,'
                'source_address,process_id,process_guid,parent_id,process_path,command_line,fields,raw,evidence_type,late_seconds,rules_done) '
                'VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1)',
                (ev_id, ev_id, t_end, received, None, 'ADMonitor.BrowserExtension', 'ADMonitor',
                 host, collector['id'], ev_id, dl['user_sid'], dl['account'], None,
                 dl['device_id'], dl['device_id'], 'Strong: enrolled browser profile + OS SID', 'download', 'observed',
                 dl.get('final_path'), dl.get('canonical_path'), None, None, None, None, dl.get('browser_name'), None,
                 js({'bytes': total_bytes, 'completed_files': len(completed_dls)}), dl['raw_sanitized_evidence'],
                 'browser_download', 0.0)
            )
            ev_row = dict(c.execute('SELECT * FROM events WHERE id=?', (ev_id,)).fetchone())
            detail = (
                f"Completed browser download volume reached {total_bytes} bytes across {len(completed_dls)} completed file(s) "
                f"within {cfg['window_seconds']}s window. Inbound download volume is not outbound exfiltration."
            )
            emit(c, vol_rule, ev_row, [ev_row], detail, total_bytes, policy)

def evaluate_domain_policy_rule(c, prof: dict, domain: str, nav_time: str, nav_id: str, policy: dict):
    """Explicit administrator-maintained lab domain policy check, clearly labeled as policy rather than threat intelligence."""
    rule = c.execute("SELECT * FROM rules WHERE id='domain_policy' AND enabled=1").fetchone()
    if not rule:
        return
    cfg = obj(rule['config'])
    policy_domains = [str(d).strip().casefold() for d in (cfg.get('paths') or policy.get('restricted_domains') or []) if str(d).strip()]
    if not policy_domains:
        return
    if any(domain == pd or domain.endswith('.' + pd) for pd in policy_domains):
        from .rules import emit
        ev_id = digest(f"dom_pol_ev:{nav_id}")
        host = _device_hostname(c, prof['device_id'])
        c.execute(
            'INSERT OR IGNORE INTO events(id,identity,time,received_at,event_id,provider,channel,source_computer,collector_id,'
            'source_record,user_sid,account,logon_id,device_id,access_device_id,attribution,category,result,object_path,canonical_path,'
            'source_address,process_id,process_guid,parent_id,process_path,command_line,fields,raw,evidence_type,late_seconds,rules_done) '
            'VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1)',
            (ev_id, ev_id, nav_time, now(), None, 'ADMonitor.BrowserExtension', 'ADMonitor',
             host, prof['collector_id'], ev_id, prof['user_sid'], prof['account'], None,
             prof['device_id'], prof['device_id'], 'Strong: enrolled browser profile + OS SID', 'domain_policy', 'observed',
             domain, domain, None, None, None, None, prof['browser_name'], None,
             js({'domain': domain, 'policy_type': 'administrator_configured_domain_list'}),
             js({'navigation_id': nav_id, 'domain': domain}), 'browser_navigation', 0.0)
        )
        ev_row = dict(c.execute('SELECT * FROM events WHERE id=?', (ev_id,)).fetchone())
        detail = (
            f"Explicit administrator-maintained lab domain policy match on '{domain}'. "
            f"This reflects local lab policy configuration, not external threat intelligence or proof of maliciousness."
        )
        emit(c, rule, ev_row, [ev_row], detail, 1, policy)
