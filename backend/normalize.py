"""Provider-specific normalization. Raw evidence remains intact; no message-text inference."""
import ntpath
from defusedxml import ElementTree as ET
from .db import stamp, dt, js, digest, uid
NS={'e':'http://schemas.microsoft.com/win/2004/08/events/event'}
SEC='Microsoft-Windows-Security-Auditing'

def canonical(path, mappings=()):
    if not path: return None
    p=path.replace('/', '\\')
    if p.startswith('\\??\\'): p=p[4:]
    p=ntpath.normpath(p).casefold()
    for m in sorted(mappings,key=lambda x:len(x['source']),reverse=True):
        src=ntpath.normpath(m['source']).casefold().rstrip('\\')
        if p==src or p.startswith(src+'\\'): return ntpath.normpath(m['target']).casefold().rstrip('\\')+p[len(src):]
    return p
def scoped(path, roots):
    return bool(path) and any(path==canonical(r) or path.startswith(canonical(r).rstrip('\\')+'\\') for r in roots)
def number(value):
    try: return int(value, 16 if str(value).lower().startswith('0x') else 10)
    except (ValueError,TypeError): return 0

def parse_xml(xml, collector_id, received, mappings=()):
    if len(xml.encode('utf-8'))>131072: raise ValueError('XML exceeds 128 KiB')
    root=ET.fromstring(xml)
    if root.tag!='{'+NS['e']+'}Event': raise ValueError('Expected Windows Event XML namespace')
    def text(key):
        v=root.find('e:System/e:'+key,NS); return v.text if v is not None else None
    fields={e.get('Name',f'field_{i}'):e.text for i,e in enumerate(root.findall('e:EventData/e:Data',NS))}
    # Preserve structured UserData too, even for providers with unfamiliar schemas.
    for e in root.findall('e:UserData//*',NS):
        if e.text and e.text.strip(): fields.setdefault(e.tag.split('}')[-1],e.text)
    prov=root.find('e:System/e:Provider',NS); time=root.find('e:System/e:TimeCreated',NS)
    if prov is None or time is None: raise ValueError('Missing provider or event time')
    provider=prov.get('Name') or prov.get('Guid'); when=stamp(time.get('SystemTime'))
    computer=text('Computer'); channel=text('Channel'); record=text('EventRecordID')
    if not computer or not channel or not record: raise ValueError('Missing source computer/channel/record identity')
    eid=int(text('EventID')); keywords=number(text('Keywords')); mask=number(fields.get('AccessMask'))
    failure=bool(keywords & 0x10000000000000); success=bool(keywords & 0x20000000000000)
    result='denied' if failure else 'success' if success else 'unknown'
    category='other'; user_prefix='Subject'; path=fields.get('ObjectName'); pid=fields.get('ProcessId')
    process=fields.get('ProcessName'); command=None; parent=None; guid=None
    if provider==SEC:
        if eid in (4624,4625): category='sign_in'; user_prefix='Target'; result='success' if eid==4624 else 'denied'
        elif eid in (4771,4740): category='sign_in'; user_prefix='Target'; result='denied'
        elif eid in (4768,4769,4776):
            user_prefix='Target'
            st=str(fields.get('Status') or fields.get('ErrorCode') or '0x0').strip().lower()
            if st not in ('0x0','0') or failure: category='sign_in'; result='denied'
        elif eid in (4634,4647): category='sign_out'; user_prefix='Target' if eid==4634 else 'Subject'
        elif eid==4656: category='access_request'
        elif eid==4663:
            result='success'
            category='file_read' if mask&1 else 'file_write' if mask&6 else 'file_delete' if mask&0x10000 else 'file_access'
        elif eid==5145:
            category='share_check'
            local=fields.get('ShareLocalPath'); relative=fields.get('RelativeTargetName')
            path=ntpath.join(local,relative) if local and relative else None
        elif eid in (4728,4732,4756):
            category='privilege_change'; user_prefix='Subject'; path=fields.get('TargetUserName')
        elif eid==4688:
            category='process_start'; pid=fields.get('NewProcessId'); process=fields.get('NewProcessName'); command=fields.get('CommandLine'); parent=fields.get('ProcessId')
        elif eid==4689: category='process_end'
        elif eid in (1102,): category='log_cleared'
    elif provider=='Microsoft-Windows-Sysmon':
        user=fields.get('User'); guid=fields.get('ProcessGuid'); pid=fields.get('ProcessId')
        process=fields.get('Image'); command=fields.get('CommandLine'); parent=fields.get('ParentProcessGuid')
        category={1:'process_start',5:'process_end',11:'file_create',15:'file_stream',23:'file_delete',26:'file_delete'}.get(eid,'other')
        path=fields.get('TargetFilename'); result='observed'
    elif provider=='Microsoft-Windows-Windows Defender' and eid in (1116,1117):
        category='antivirus_detection' if eid==1116 else 'antivirus_action'; result='observed'; path=fields.get('Path')
    elif provider=='Microsoft-Windows-PowerShell' and eid==4104:
        category='script_block'; result='observed'; path=fields.get('Path'); command=fields.get('ScriptBlockText')
    sid=fields.get(user_prefix+'UserSid') or fields.get(user_prefix+'Sid')
    if sid=='S-1-0-0': sid=None
    name=fields.get(user_prefix+'UserName'); domain=fields.get(user_prefix+'DomainName')
    account=(domain+'\\' if domain and domain!='-' else '')+name if name and name!='-' else fields.get('User')
    identity=digest(js([computer.casefold(),provider,channel.casefold(),record,when,eid,sorted(fields.items())]))
    return dict(id=uid(),identity=identity,time=when,received_at=received,event_id=eid,provider=provider,channel=channel,
        source_computer=computer,collector_id=collector_id,source_record=record,user_sid=sid,account=account,
        logon_id=fields.get(user_prefix+'LogonId'),device_id=None,access_device_id=None,attribution='Unknown',category=category,
        result=result,object_path=path,canonical_path=canonical(path,mappings),source_address=fields.get('IpAddress') or fields.get('SourceIp'),
        process_id=pid,process_guid=guid,parent_id=parent,process_path=process,command_line=command,
        fields=js(fields),raw=xml,evidence_type='windows_event_xml',late_seconds=(dt(received)-dt(when)).total_seconds())
