import { useState, useEffect, useContext } from 'react';
import { useParams, Link } from 'react-router-dom';
import {
  Fingerprint, CircleDot, FileText, ShieldAlert, CheckCircle2,
  User, Users, Monitor, Shield, FileCheck, ShieldCheck, Settings,
  Clock, ArrowUpRight, ChevronRight, HardDrive, Cpu, Activity, Download
} from 'lucide-react';
import {
  Context, useData, api, Page, Panel, Badge, Empty, ErrorBox,
  Time, EventTable, AlertList, Pager, Json, Facts, formatBytes, timeAgo, HealthBar
} from './core';
import type { Data } from './core';
import { getMitre } from './mitre';
import { ExecutiveDossier } from './ExecutiveDossier';

export function Alerts() {
  const { period, bump } = useContext(Context);
  const [f, setF] = useState<Data>({});
  const [page, setPage] = useState(1);
  const { data, error } = useData('/alerts?' + period + '&' + new URLSearchParams({ ...f, page: String(page) }));

  return (
    <Page
      title="Alerts & investigations"
      description="Explainable findings. Human decisions. A persistent review trail."
      action={
        <button
          type="button"
          className="button"
          style={{ borderColor: '#ef4444', color: '#ef4444' }}
          onClick={async () => {
            await api('/admin/reset-telemetry', { method: 'POST' });
            bump();
          }}
        >
          Reset All to 0
        </button>
      }
    >
      <div className="filters">
        {[
          ['status', ['Open', 'Investigating', 'Closed'], 'All statuses'],
          ['severity', ['High', 'Medium', 'Low'], 'All severities'],
          ['kind', ['rule', 'model'], 'Rules & model findings']
        ].map(([k, opts, label]: any) => (
          <select key={k} aria-label={label} value={f[k] || ''} onChange={e => { setF({ ...f, [k]: e.target.value }); setPage(1); }}>
            <option value="">{label}</option>
            {opts.map((s: string) => <option key={s}>{s}</option>)}
          </select>
        ))}
      </div>
      <ErrorBox message={error} />
      {data && (
        <Panel title="Findings in selected period">
          <AlertList items={data.items} />
          <Pager data={data} page={page} setPage={setPage} />
        </Panel>
      )}
    </Page>
  );
}

function getReadableSubtitle(d: Data): string {
  const rid = d.rule_id || d.explanation?.rule_id;
  const dept = d.employee?.department || 'Sales';
  const acct = d.employee?.name || d.account || 'A domain account';
  if (rid === 'restricted') return `${acct} attempted to read a restricted HR document.`;
  if (rid === 'privilege_attack') return `An unauthorized modification to privileged security group membership was detected.`;
  if (rid === 'usb_copy') return `A file copy operation to removable flash storage was observed on the employee workstation.`;
  if (rid === 'c2_beacon') return `Recurring outbound network connections detected matching an automated beaconing pattern.`;
  if (rid === 'suspicious_powershell') return `PowerShell execution with encoded commands or download cradles was captured in audit logs.`;
  if (rid === 'canary') return `Access to a decoy honeytoken file was recorded; canary files have no legitimate business use.`;
  if (rid === 'bulk') return `Rapid sequential reading of confidential files exceeding normal operational baseline.`;
  if (rid === 'staging') return `Files were staged into a local folder and compressed into an archive.`;
  return d.explanation?.detail || d.explanation?.summary || 'Observed Windows security telemetry matched configured detection criteria.';
}

export function Investigation() {
  const { id } = useParams();
  const { user, bump, timezone } = useContext(Context);
  const { data: d, error } = useData('/alerts/' + id);
  const { data: users } = useData(user.role === 'Viewer' ? null : '/users');
  const [form, setForm] = useState({ status: 'Open', disposition: '', assigned_to: '', note: '' });
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);
  const [showDossier, setShowDossier] = useState(false);

  useEffect(() => {
    if (d) setForm(v => ({ ...v, status: d.status, disposition: d.disposition || '', assigned_to: d.assigned_to || '' }));
  }, [d?.id, d?.status, d?.disposition, d?.assigned_to]);

  const mitre = d ? getMitre(d.rule_id || d.explanation?.rule_id) : null;
  const firstEv = d?.evidence?.[0];

  return (
    <div className="investigation-view">
      {showDossier && d && <ExecutiveDossier alert={d} onClose={() => setShowDossier(false)} />}
      
      {/* Breadcrumb Header */}
      <div className="investigation-breadcrumb">
        <Link to="/alerts">Alerts</Link>
        <span>/</span>
        <strong>Investigation</strong>
        <span className="investigation-case-id">CASE-{id?.slice(0, 8).toUpperCase()}</span>
      </div>

      <ErrorBox message={error || err} />

      {d && (
        <>
          {/* Main Title Row */}
          <div className="investigation-header-row">
            <div>
              <div className="investigation-title-wrap">
                <h1>{d.title}</h1>
                <Badge tone={d.status === 'Open' ? 'investigating' : d.status}>
                  {d.status === 'Open' ? 'Needs review' : d.status}
                </Badge>
                <Badge tone={d.severity}>{d.severity} Severity</Badge>
              </div>
              <p className="investigation-subtitle">{getReadableSubtitle(d)}</p>
            </div>
            <div className="actions" style={{ flexWrap: 'wrap' }}>
              <Link
                className="button"
                to={`/attack-library/${d.rule_id || d.explanation?.rule_id || 'restricted'}?alertId=${id}`}
              >
                <Shield size={14} /> Explain this attack type
              </Link>
              <Link
                className="button primary"
                to={`/present/case/${id}`}
              >
                <Monitor size={14} /> Present this case
              </Link>
              <button onClick={() => setShowDossier(true)}>
                <FileText size={15} /> Executive Dossier
              </button>
              <button onClick={() => window.print()}>Print case</button>
              <a className="button" href={'/api/reports/cases/' + id}>
                <Download size={14} /> Export JSON
              </a>
            </div>
          </div>

          {/* 4 Summary Stat Cards */}
          <div className="investigation-stat-cards">
            <div className="inv-stat-card">
              <div className="inv-stat-icon blue"><User size={20} /></div>
              <div>
                <small>Employee</small>
                <strong>{d.employee?.name || d.account || d.user_sid || 'Unknown identity'}</strong>
              </div>
            </div>
            <div className="inv-stat-card">
              <div className="inv-stat-icon teal"><Users size={20} /></div>
              <div>
                <small>Department</small>
                <strong>{d.employee?.department || 'Unknown'}</strong>
              </div>
            </div>
            <div className="inv-stat-card">
              <div className="inv-stat-icon violet"><Monitor size={20} /></div>
              <div>
                <small>Device</small>
                <strong>{d.device?.hostname || d.access_device_id || 'Unknown device'}</strong>
              </div>
            </div>
            <div className="inv-stat-card">
              <div className="inv-stat-icon red"><Shield size={20} /></div>
              <div>
                <small>Outcome</small>
                <strong>{firstEv?.result === 'denied' ? 'Access denied' : (firstEv?.result || 'Observed')}</strong>
              </div>
            </div>
          </div>

          {/* Main Content 2-Column Grid */}
          <div className="grid case-grid">
            {/* Left Column: Evidence & Analysis */}
            <div>
              {/* Why this was flagged Panel */}
              <Panel
                title="Why this was flagged"
                subtitle={d.kind === 'model' ? 'Behavior model finding · statistical anomaly' : 'Rule-based detection · not an AI verdict'}
              >
                <div className="why-flagged-content">
                  <p className="why-flagged-desc">
                    {d.explanation?.detail || `The account belongs to ${d.employee?.department || 'an observed department'}. The requested action violated configured security boundary policy.`}
                  </p>
                  
                  <div className="why-flagged-highlights">
                    <div className="flagged-highlight-card">
                      <div className="highlight-icon"><FileCheck size={18} /></div>
                      <div>
                        <small>Observed</small>
                        <strong>{d.explanation?.observed || 1} {firstEv?.result || 'observed'} attempt</strong>
                        <span>to target resource</span>
                      </div>
                    </div>

                    <div className="flagged-highlight-card">
                      <div className="highlight-icon"><ShieldCheck size={18} /></div>
                      <div>
                        <small>Policy</small>
                        <strong>{d.explanation?.threshold || 1} or more attempts</strong>
                        <span>threshold in {d.explanation?.window_seconds || 300}s window</span>
                      </div>
                    </div>

                    <div className="flagged-highlight-card">
                      <div className="highlight-icon"><Settings size={18} /></div>
                      <div>
                        <small>Detection source</small>
                        <strong>{d.kind === 'model' ? 'Isolation Forest UBA' : 'Windows audit rule'}</strong>
                        <span>{firstEv?.provider || 'Security Event'}</span>
                      </div>
                    </div>
                  </div>
                </div>

                <div className="raw-evidence-accordions">
                  <details>
                    <summary>Raw Windows event evidence ({d.evidence_total || d.evidence?.length || 0} source records)</summary>
                    <Json value={firstEv?.raw || firstEv?.fields || d.evidence} />
                  </details>
                  <details>
                    <summary>Rule configuration snapshot</summary>
                    <Json value={d.config_snapshot} />
                  </details>
                </div>
              </Panel>

              {/* Evidence Timeline Panel */}
              <Panel
                title="Evidence timeline"
                subtitle="Key events related to this alert, in chronological order."
              >
                <div className="evidence-stepper">
                  {/* Step 1: Session Identification */}
                  <div className="stepper-step">
                    <div className="stepper-num">1</div>
                    <div className="stepper-time">
                      {firstEv ? new Date(firstEv.time).toLocaleTimeString('en-GB') : '—'}
                    </div>
                    <div className="stepper-body">
                      <strong>Employee session identified</strong>
                      <p>User {d.account || d.user_sid || 'Unknown identity'} observed on {d.device?.hostname || d.access_device_id || 'Unknown device'}.</p>
                    </div>
                  </div>

                  {/* Step 2: Target Attempt / Action */}
                  <div className="stepper-step">
                    <div className="stepper-num red">2</div>
                    <div className="stepper-time">
                      {new Date(d.last_time).toLocaleTimeString('en-GB')}
                    </div>
                    <div className="stepper-body">
                      <strong>{d.title}</strong>
                      <p>{getReadableSubtitle(d)}</p>
                      {firstEv?.object_path && (
                        <div className="stepper-path-pill">
                          <HardDrive size={13} />
                          <span>{firstEv.object_path.replace(/\\/g, ' / ')}</span>
                        </div>
                      )}
                      {firstEv?.command_line && (
                        <div className="stepper-path-pill command">
                          <code>{firstEv.command_line}</code>
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Step 3: Alert Ingestion */}
                  <div className="stepper-step">
                    <div className="stepper-num amber">3</div>
                    <div className="stepper-time">
                      {new Date(d.created_at).toLocaleTimeString('en-GB')}
                    </div>
                    <div className="stepper-body">
                      <strong>Alert created from audit evidence</strong>
                      <p>A normalized Windows security event matched the access policy rule.</p>
                    </div>
                  </div>
                </div>

                {/* Supporting Evidence Table */}
                {d.evidence && d.evidence.length > 0 && (
                  <div style={{ marginTop: '20px', borderTop: '1px solid var(--border)', paddingTop: '16px' }}>
                    <h4 style={{ fontSize: '12px', margin: '0 0 10px', color: 'var(--text)' }}>
                      Supporting Normalized Records ({d.evidence_total || d.evidence.length})
                    </h4>
                    <EventTable items={d.evidence.slice(0, 10)} />
                  </div>
                )}
              </Panel>

              {/* Review History Panel */}
              <Panel title="Review history">
                {d.history && d.history.length ? (
                  <div className="timeline">
                    {d.history.map((h: Data) => (
                      <div key={h.id}>
                        <CircleDot size={14} />
                        <div>
                          <strong>{h.actor} · {h.action}</strong>
                          <small><Time value={h.time} /></small>
                          <Json value={h.body} />
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <Empty title="Awaiting first review">
                    Notes and status decisions retain the reviewer identity.
                  </Empty>
                )}
              </Panel>
            </div>

            {/* Right Column: Device Health & Review Form */}
            <div>
              {/* Device Health Panel */}
              <Panel
                title="Device health"
                action={
                  <Badge tone={d.device?.presence === 'Online' ? 'online' : (d.device?.presence || 'stale')}>
                    {d.device?.presence || 'Stale'}
                  </Badge>
                }
              >
                <div className="device-health-widget">
                  <div className="dev-header">
                    <Monitor size={22} style={{ color: '#0284c7' }} />
                    <div>
                      <strong>{d.device?.hostname || d.access_device_id || 'Unknown device'}</strong>
                      <small>Last heartbeat: {timeAgo(d.device?.last_heartbeat)}</small>
                    </div>
                  </div>

                  <div className="dev-metrics-list">
                    <div className="dev-metric-row">
                      <span>CPU</span>
                      <div className="dev-metric-bar">
                        {d.device?.health?.cpu != null ? (
                          <>
                            <HealthBar percent={d.device.health.cpu} color="#10b981" />
                            <small>{d.device.health.cpu.toFixed(0)}%</small>
                          </>
                        ) : (
                          <small style={{ color: 'var(--muted)' }}>Not collected in latest heartbeat</small>
                        )}
                      </div>
                    </div>

                    <div className="dev-metric-row">
                      <span>Memory</span>
                      <div className="dev-metric-bar">
                        {d.device?.health?.ram_percent != null ? (
                          <>
                            <HealthBar percent={d.device.health.ram_percent} color="#0284c7" />
                            <small>
                              {d.device.health.ram_percent.toFixed(0)}% · {formatBytes(d.device.health.ram_used)} / {formatBytes(d.device.health.ram_total)}
                            </small>
                          </>
                        ) : (
                          <small style={{ color: 'var(--muted)' }}>Not collected in latest heartbeat</small>
                        )}
                      </div>
                    </div>

                    <div className="dev-session-row">
                      <small>Observed account</small>
                      <strong>{d.account || d.user_sid || 'Unknown identity'}</strong>
                    </div>
                  </div>
                </div>
              </Panel>

              {/* Analyst Review Panel */}
              {user.role !== 'Viewer' && (
                <Panel title="Analyst review">
                  <form
                    className="stack"
                    onSubmit={async e => {
                      e.preventDefault();
                      setBusy(true);
                      try {
                        await api('/alerts/' + id, {
                          method: 'PATCH',
                          body: JSON.stringify({ ...form, disposition: form.disposition || null, assigned_to: form.assigned_to || null })
                        });
                        setForm({ ...form, note: '' });
                        setErr('');
                        bump();
                      } catch (e: any) {
                        setErr(e.message);
                      } finally {
                        setBusy(false);
                      }
                    }}
                  >
                    <label>
                      Status
                      <select value={form.status} onChange={e => setForm({ ...form, status: e.target.value })}>
                        {['Open', 'Investigating', 'Closed'].map(s => (
                          <option key={s} value={s}>{s === 'Open' ? 'Needs review' : s}</option>
                        ))}
                      </select>
                    </label>

                    <label>
                      Disposition
                      <select value={form.disposition} onChange={e => setForm({ ...form, disposition: e.target.value })}>
                        <option value="">Not reviewed</option>
                        {['suspicious', 'benign', 'false_positive'].map(s => <option key={s}>{s}</option>)}
                      </select>
                    </label>

                    <label>
                      Assigned reviewer
                      <select value={form.assigned_to} onChange={e => setForm({ ...form, assigned_to: e.target.value })}>
                        <option value="">Unassigned</option>
                        {users?.filter((u: Data) => u.enabled && u.role !== 'Viewer').map((u: Data) => (
                          <option key={u.id} value={u.id}>{u.username}</option>
                        ))}
                      </select>
                    </label>

                    <label>
                      Analyst notes
                      <textarea
                        rows={5}
                        value={form.note}
                        onChange={e => setForm({ ...form, note: e.target.value })}
                        placeholder="Add findings and context…"
                      />
                    </label>

                    <small style={{ color: 'var(--muted)', fontSize: '10.5px' }}>
                      Verify role, access policy and source evidence before deciding.
                    </small>

                    <button className="primary" disabled={busy}>
                      {busy ? 'Saving…' : 'Save review'}
                    </button>
                  </form>
                </Panel>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
