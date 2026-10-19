import pytest
from backend.normalize import canonical, scoped, parse_xml
from backend.db import now

MAPPINGS = [
    {"source": "\\\\WIN-8IIRPFSV4GI.lab.local\\ADMonitor-Demo", "target": "C:\\ADMonitor-Demo"}
]

def test_canonical_path():
    p1 = "\\\\WIN-8IIRPFSV4GI.lab.local\\ADMonitor-Demo\\Sales\\Demo-File-1.txt"
    assert canonical(p1, MAPPINGS) == "c:\\admonitor-demo\\sales\\demo-file-1.txt"

    p2 = "C:/ADMonitor-Demo/HR/Demo-File-2.txt"
    assert canonical(p2, MAPPINGS) == "c:\\admonitor-demo\\hr\\demo-file-2.txt"

    assert canonical(None, MAPPINGS) is None

def test_scoped_paths():
    roots = ["C:\\ADMonitor-Demo\\Sensitive", "C:\\ADMonitor-Demo\\HR"]
    assert scoped("c:\\admonitor-demo\\sensitive\\file1.txt", roots) is True
    assert scoped("c:\\admonitor-demo\\hr\\payroll.xlsx", roots) is True
    assert scoped("c:\\admonitor-demo\\sales\\demo.txt", roots) is False

def test_parse_xml_4663_file_read():
    xml = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4663</EventID>
    <TimeCreated SystemTime="2026-10-02T10:00:00.000000Z"/>
    <EventRecordID>1001</EventRecordID>
    <Channel>Security</Channel>
    <Computer>WIN-8IIRPFSV4GI.lab.local</Computer>
    <Keywords>0x8020000000000000</Keywords>
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-21-123-456-789-1002</Data>
    <Data Name="SubjectUserName">sales.demo</Data>
    <Data Name="SubjectDomainName">LAB</Data>
    <Data Name="ObjectName">C:\\ADMonitor-Demo\\Sales\\Demo-File-1.txt</Data>
    <Data Name="AccessMask">0x1</Data>
  </EventData>
</Event>"""
    ev = parse_xml(xml, "col_1", now(), MAPPINGS)
    assert ev["event_id"] == 4663
    assert ev["category"] == "file_read"
    assert ev["result"] == "success"
    assert ev["account"] == "LAB\\sales.demo"
    assert ev["canonical_path"] == "c:\\admonitor-demo\\sales\\demo-file-1.txt"
    assert ev["evidence_type"] == "windows_event_xml"

def test_parse_xml_4656_access_denied():
    xml = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4656</EventID>
    <TimeCreated SystemTime="2026-10-02T10:05:00.000000Z"/>
    <EventRecordID>1002</EventRecordID>
    <Channel>Security</Channel>
    <Computer>WIN-8IIRPFSV4GI.lab.local</Computer>
    <Keywords>0x8010000000000000</Keywords>
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-21-123-456-789-1002</Data>
    <Data Name="SubjectUserName">sales.demo</Data>
    <Data Name="SubjectDomainName">LAB</Data>
    <Data Name="ObjectName">C:\\ADMonitor-Demo\\HR\\Demo-File-1.txt</Data>
    <Data Name="AccessMask">0x1</Data>
  </EventData>
</Event>"""
    ev = parse_xml(xml, "col_1", now(), MAPPINGS)
    assert ev["event_id"] == 4656
    assert ev["category"] == "access_request"
    assert ev["result"] == "denied"
    assert ev["canonical_path"] == "c:\\admonitor-demo\\hr\\demo-file-1.txt"

def test_parse_defender_1116():
    xml = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Windows Defender"/>
    <EventID>1116</EventID>
    <TimeCreated SystemTime="2026-10-02T10:10:00.000000Z"/>
    <EventRecordID>2001</EventRecordID>
    <Channel>Microsoft-Windows-Windows Defender/Operational</Channel>
    <Computer>LAB-PC01.lab.local</Computer>
  </System>
  <EventData>
    <Data Name="Path">C:\\Users\\sales.demo\\Downloads\\eicar.txt</Data>
    <Data Name="ThreatName">Virus:DOS/EICAR_Test_File</Data>
  </EventData>
</Event>"""
    ev = parse_xml(xml, "col_2", now(), MAPPINGS)
    assert ev["event_id"] == 1116
    assert ev["category"] == "antivirus_detection"
    assert ev["result"] == "observed"
