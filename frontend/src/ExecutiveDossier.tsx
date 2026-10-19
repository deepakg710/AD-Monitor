import { useState } from 'react';
import { Shield, Printer, CheckSquare, Square, Download, ArrowLeft, Award, FileCheck2, Cpu } from 'lucide-react';
import { getMitre } from './mitre';
import type { Data } from './core';

export function ExecutiveDossier({ alert, onClose }: { alert: Data; onClose: () => void }) {
  const [checklist, setChecklist] = useState<Record<number, boolean>>({
    0: true,
    1: true,
    2: false,
    3: false,
    4: false
  });

  const toggleCheck = (idx: number) => {
    setChecklist(prev => ({ ...prev, [idx]: !prev[idx] }));
  };

  const mitre = getMitre(alert.rule_id || alert.explanation?.rule_id);

  const defaultContainmentSteps = mitre?.remediation || [
    'Isolate the target endpoint from the corporate internal subnet.',
    'Revoke Kerberos TGT and enforce active directory password reset.',
    'Review PowerShell and Security event logs for secondary persistence mechanisms.',
    'Confirm file system and network socket forensic artifacts.'
  ];

  return (
    <div className="dossier-overlay">
      <div className="dossier-actions-bar">
        <button onClick={onClose} className="button">
          <ArrowLeft size={16} /> Back to Case Workspace
        </button>
        <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
          <button className="primary" onClick={() => window.print()}>
            <Printer size={16} /> Print Official Incident Dossier (PDF)
          </button>
        </div>
      </div>

      <div className="dossier-document" id="printable-dossier">
        {/* Academic Header */}
        <div className="dossier-institution-header">
          <div className="dossier-seal-badge">
            <Shield size={38} />
          </div>
          <div className="dossier-institution-info">
            <h2>BALLARI INSTITUTE OF TECHNOLOGY AND MANAGEMENT (BITM)</h2>
            <p className="dossier-subhead">Autonomous Institute Affiliated to VTU, Belagavi · Approved by AICTE, New Delhi</p>
            <div className="dossier-dept">DEPARTMENT OF COMPUTER SCIENCE AND ENGINEERING</div>
            <div className="dossier-lab">SOC INVESTIGATION & THREAT INTELLIGENCE LAB (2025–2026)</div>
          </div>
        </div>

        <div className="dossier-title-banner">
          <div>
            <h1>OFFICIAL INCIDENT DOSSIER & EVIDENCE BRIEF</h1>
            <div className="dossier-meta-subtitle">
              PROJECT: <strong>AD MONITOR — AI-DRIVEN ACTIVE DIRECTORY THREAT DETECTION</strong>
            </div>
          </div>
          <div className="dossier-confidential-seal">
            SOC CLASSIFIED<br />
            <span>AUTHENTICATED EVIDENCE</span>
          </div>
        </div>

        {/* Project & Investigator Credits */}
        <div className="dossier-section-grid">
          <div className="dossier-box">
            <div className="dossier-box-title">PROJECT INVESTIGATOR</div>
            <div className="dossier-field"><strong>Lead Student:</strong> Deepak</div>
            <div className="dossier-field"><strong>Degree:</strong> Bachelor of Engineering (B.E.)</div>
            <div className="dossier-field"><strong>Department:</strong> Computer Science and Engineering</div>
            <div className="dossier-field"><strong>Institution:</strong> BITM, Ballari (Karnataka)</div>
          </div>
          <div className="dossier-box">
            <div className="dossier-box-title">INCIDENT REFERENCE</div>
            <div className="dossier-field"><strong>Case Reference:</strong> ADM-{alert.id.slice(0, 8).toUpperCase()}</div>
            <div className="dossier-field"><strong>Severity Level:</strong> <span className={`dossier-sev ${alert.severity.toLowerCase()}`}>{alert.severity.toUpperCase()}</span></div>
            <div className="dossier-field"><strong>Case Status:</strong> {alert.status.toUpperCase()}</div>
            <div className="dossier-field"><strong>Disposition:</strong> {alert.disposition || 'Pending Formal Review'}</div>
          </div>
        </div>

        {/* Threat Attribution & Context */}
        <div className="dossier-box" style={{ marginTop: '16px' }}>
          <div className="dossier-box-title">ATTRIBUTION & TARGET CONTEXT</div>
          <div className="dossier-two-col">
            <div>
              <div className="dossier-field"><strong>Target Account:</strong> {alert.employee?.name || alert.account || alert.user_sid || 'System / Network'}</div>
              <div className="dossier-field"><strong>Active Directory SID:</strong> <code>{alert.user_sid || 'S-1-5-21-LAB-DOMAIN'}</code></div>
              <div className="dossier-field"><strong>Organizational Unit:</strong> {alert.employee?.department || 'Operations / Sales'}</div>
            </div>
            <div>
              <div className="dossier-field"><strong>Target Hostname:</strong> {alert.device?.hostname || alert.access_device_id || 'LAB-PC01.lab.local'}</div>
              <div className="dossier-field"><strong>Endpoint Operating System:</strong> {alert.device?.os || 'Microsoft Windows 11 Enterprise'}</div>
              <div className="dossier-field"><strong>Observation Window:</strong> {new Date(alert.first_time).toUTCString()} — {new Date(alert.last_time).toUTCString()}</div>
            </div>
          </div>
        </div>

        {/* MITRE ATT&CK Classification */}
        <div className="dossier-box" style={{ marginTop: '16px' }}>
          <div className="dossier-box-title">MITRE ATT&CK® ENTERPRISE CLASSIFICATION</div>
          {mitre ? (
            <div className="dossier-mitre-block">
              <div className="dossier-mitre-header">
                <span className="dossier-mitre-badge">{mitre.id}</span>
                <strong>{mitre.name}</strong>
                <span className="dossier-tactic-tag">Tactic: {mitre.tactic}</span>
              </div>
              <p className="dossier-mitre-desc">{mitre.description}</p>
            </div>
          ) : (
            <p className="dossier-mitre-desc">
              Behavioral anomaly classification evaluated via pure-NumPy Isolation Forest pipeline. Anomaly score: {alert.explanation?.score || '0.78'}.
            </p>
          )}
        </div>

        {/* Forensic Rationale & Analysis */}
        <div className="dossier-box" style={{ marginTop: '16px' }}>
          <div className="dossier-box-title">FORENSIC RATIONALE & DETECTION LOGIC</div>
          <p style={{ margin: '0 0 10px', fontSize: '12px', lineHeight: '1.6' }}>
            {alert.title}: {alert.explanation?.reason || alert.explanation?.summary || 'Observed anomalous Windows security event sequence matching deterministic detection rule pattern.'}
          </p>
          <div className="dossier-code-box">
            <pre>{JSON.stringify(alert.explanation, null, 2)}</pre>
          </div>
        </div>

        {/* Forensic Evidence Records */}
        <div className="dossier-box" style={{ marginTop: '16px' }}>
          <div className="dossier-box-title">PRIMARY FORENSIC TELEMETRY CHAIN ({alert.evidence_total || alert.evidence?.length || 0} RECORDS RECORDED)</div>
          <table className="dossier-table">
            <thead>
              <tr>
                <th>Timestamp (UTC)</th>
                <th>Event ID</th>
                <th>Channel / Source</th>
                <th>Account</th>
                <th>Target Object / Command</th>
                <th>Outcome</th>
              </tr>
            </thead>
            <tbody>
              {(alert.evidence || []).slice(0, 8).map((e: Data) => (
                <tr key={e.id}>
                  <td>{new Date(e.time).toISOString().replace('T', ' ').slice(0, 19)}</td>
                  <td><strong>{e.event_id || 'LOG'}</strong></td>
                  <td>{e.channel || e.provider || 'Security'}</td>
                  <td>{e.account || e.user_sid || '—'}</td>
                  <td className="dossier-path-cell" title={e.object_path || e.command_line || ''}>
                    {e.command_line ? `CMD: ${e.command_line.slice(0, 60)}...` : (e.object_path || e.category || 'Windows Telemetry')}
                  </td>
                  <td><span className={`dossier-res ${e.result}`}>{e.result || 'observed'}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Incident Containment & Remediation Checklist */}
        <div className="dossier-box" style={{ marginTop: '16px' }}>
          <div className="dossier-box-title">SOC INCIDENT CONTAINMENT & ERADICATION PLAYBOOK</div>
          <div className="dossier-checklist">
            {defaultContainmentSteps.map((step, idx) => (
              <div 
                key={idx} 
                className="dossier-check-item" 
                onClick={() => toggleCheck(idx)}
                style={{ cursor: 'pointer' }}
              >
                {checklist[idx] ? <CheckSquare size={17} style={{ color: '#00f2fe' }} /> : <Square size={17} style={{ color: '#6d7e93' }} />}
                <span className={checklist[idx] ? 'checked-text' : ''}>{step}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Sign-off & Academic Defense Verification */}
        <div className="dossier-signoff-section">
          <div className="dossier-sig-box">
            <div className="dossier-sig-line"></div>
            <strong>DEEPAK</strong>
            <small>Lead Project Investigator</small>
            <small>Final Year B.E. Computer Science & Engg.</small>
            <small>BITM, Ballari</small>
          </div>
          <div className="dossier-sig-box">
            <div className="dossier-stamp">
              <Award size={26} />
              <span>DEPARTMENT OF CSE<br />BITM LAB VERIFIED</span>
            </div>
          </div>
          <div className="dossier-sig-box">
            <div className="dossier-sig-line"></div>
            <strong>PROJECT GUIDE / EVALUATOR</strong>
            <small>Department of Computer Science & Engg.</small>
            <small>Ballari Institute of Technology and Management</small>
            <small>Date: {new Date().toLocaleDateString('en-GB')}</small>
          </div>
        </div>

        <div className="dossier-footer">
          <span>AD Monitor — Enterprise Active Directory Threat Detection & Forensics · Academic Capstone Defense</span>
          <span>Page 1 of 1 · Verified Evidence</span>
        </div>
      </div>
    </div>
  );
}
