from typing import Literal, Any
from pydantic import BaseModel, ConfigDict, Field, field_validator
from zoneinfo import ZoneInfo

class Strict(BaseModel): model_config=ConfigDict(extra='forbid')
class Login(Strict):
    username:str=Field(min_length=1,max_length=64)
    password:str=Field(min_length=1,max_length=256)
class NewUser(Login): role:Literal['Admin','Analyst','Viewer']='Viewer'
class UserUpdate(Strict):
    role:Literal['Admin','Analyst','Viewer']
    enabled:bool
class Enroll(Strict):
    name:str=Field(min_length=1,max_length=100)
    kind:Literal['bridge','wef','endpoint','directory','dc','browser']
    hostname:str|None=Field(default=None,min_length=1,max_length=255,pattern=r'^[a-zA-Z0-9.-]+$')
    expected_host:str|None=Field(default=None,min_length=1,max_length=255,pattern=r'^[a-zA-Z0-9.-]+$')
    user_sid:str|None=Field(default=None,max_length=128)
    account:str|None=Field(default=None,max_length=128)
    extension_id:str|None=Field(default=None,max_length=64)
    browser_name:Literal['Chrome','Edge']|None=None
    def resolved_host(self)->str:
        h=(self.hostname or self.expected_host or '').strip()
        if not h: raise ValueError('hostname or expected_host required')
        return h
class Record(BaseModel):
    model_config=ConfigDict(extra='ignore')
    id:str|None=Field(default=None,max_length=200)
    kind:Literal[
        'windows','heartbeat','directory','observation',
        'process_snapshot','process_lifecycle',
        'browser_enrollment','browser_navigation','browser_download','browser_status'
    ]
    time:str|None=None
    xml:str|None=Field(default=None,max_length=131072)
    data:dict[str,Any]|None=None
class Batch(BaseModel):
    model_config=ConfigDict(extra='ignore')
    schema_version:int|str=Field(default=2)
    transport_id:str|None=Field(default=None,max_length=200)
    records:list[Record]=Field(min_length=1,max_length=250)
    checkpoints:dict[str,str]=Field(default_factory=dict,max_length=20)
    diagnostics:dict[str,Any]=Field(default_factory=dict,max_length=40)
    @field_validator('records',mode='before')
    @classmethod
    def ensure_list(cls,v): return [v] if isinstance(v,dict) else v
class CollectorStatus(Strict): diagnostics:dict[str,Any]=Field(default_factory=dict,max_length=40)
class CaseUpdate(Strict):
    status:Literal['Open','Investigating','Closed']
    disposition:Literal['suspicious','benign','false_positive']|None=None
    assigned_to:str|None=None
    note:str=Field(default='',max_length=10000)
class Note(Strict): body:str=Field(min_length=1,max_length=10000)
class CorrelationReviewInput(Strict):
    state:str|None=Field(default=None,max_length=128)
    decision:str|None=Field(default=None,max_length=128)
    review_status:str|None=Field(default=None,max_length=128)
    notes:str=Field(default='',max_length=2000)
    note:str=Field(default='',max_length=2000)
    link_id:str|None=Field(default=None,max_length=128)
    def resolved_state(self)->str:
        raw = (self.state or self.decision or self.review_status or 'Needs follow-up').strip()
        mapping = {
            'Accepted': 'Confirmed policy violation',
            'Rejected': 'Benign / expected activity',
            'Benign lab activity': 'Benign / expected activity',
            'Reviewed - Benign': 'Benign / expected activity',
            'Needs review': 'Needs follow-up',
        }
        resolved = mapping.get(raw, raw)
        if resolved not in ('Unreviewed', 'Benign / expected activity', 'Needs follow-up', 'Confirmed policy violation'):
            raise ValueError('Invalid correlation review state')
        return resolved
    def resolved_notes(self)->str:
        return (self.notes or self.note or '').strip()
class RuleConfig(Strict):
    threshold:int=Field(ge=1,le=10737418240)
    window_seconds:int=Field(ge=1,le=86400)
    cooldown_seconds:int=Field(ge=1,le=86400)
    severity:Literal['High','Medium','Low']
    paths:list[str]=Field(max_length=100)
    employee_sids:list[str]=Field(max_length=500)
    device_ids:list[str]=Field(max_length=500)
class RuleUpdate(Strict):
    enabled:bool
    config:RuleConfig
class AppSettings(Strict):
    timezone:str='Asia/Kolkata'
    event_retention_days:int=Field(default=90,ge=1,le=3650)
    health_retention_days:int=Field(default=14,ge=1,le=365)
    alert_retention_days:int=Field(default=365,ge=1,le=3650)
    raw_retention_days:int=Field(default=30,ge=1,le=3650)
    process_sample_retention_days:int=Field(default=7,ge=1,le=365)
    process_lifecycle_retention_days:int=Field(default=30,ge=1,le=3650)
    browser_retention_days:int=Field(default=30,ge=1,le=3650)
    max_pending_records:int=Field(default=10000,ge=100,le=100000)
    min_free_mb:int=Field(default=256,ge=128,le=10240)
    business_start:int=Field(default=9,ge=0,le=23)
    business_end:int=Field(default=18,ge=0,le=23)
    business_days:list[int]=Field(default=[0,1,2,3,4],max_length=7)
    sensitive_paths:list[str]=Field(max_length=100)
    restricted_domains:list[str]=Field(default_factory=list,max_length=200)
    path_mappings:list[dict[str,str]]=Field(max_length=100)
    model_min_windows:int=Field(default=48,ge=24,le=10000)
    model_min_days:int=Field(default=7,ge=2,le=365)
    model_user_min_windows:int=Field(default=24,ge=12,le=10000)
    model_contamination:float=Field(default=0.05,ge=0.001,le=0.2)
    model_lateness_minutes:int=Field(default=15,ge=5,le=1440)
    @field_validator('timezone')
    @classmethod
    def zone(cls,v): ZoneInfo(v); return v
    @field_validator('business_days')
    @classmethod
    def days(cls,v):
        if any(x<0 or x>6 for x in v): raise ValueError('Weekdays must be 0–6')
        return v
    @field_validator('path_mappings')
    @classmethod
    def paths(cls,v):
        if any(set(x)!={'source','target'} or not all(x.values()) for x in v): raise ValueError('Mappings require source and target paths')
        return v
class PrimaryDevice(Strict): device_id:str
class Job(Strict): kind:Literal['train','score']
