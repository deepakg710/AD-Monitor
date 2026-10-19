import { useState, useContext } from 'react';
import { Link, useParams, useSearchParams } from 'react-router-dom';
import {
  Bell, Monitor, Activity, Database, ArrowUpRight, Download, Users,
  ShieldAlert, ChevronRight, Server, ShieldCheck, HardDrive, Info
} from 'lucide-react';
import {
  Context, useData, api, Page, Panel, Badge, Empty, ErrorBox, Time,
  EventTable, AlertList, Chart, Pager, Json, Facts, formatBytes,
  timeAgo, HealthBar, computePresence
} from './core';
import type { Data } from './core';
import { MitreMatrix } from './MitreMatrix';

function getFriendlyAction(e: Data): string {
  const cat = e.category || '';
  const path = e.object_path || '';
  if (cat === 'access_request' && e.result === 'denied') return `Failed to access ${path || '\\\\fileserver\\HR'}`;
  if (cat === 'file_read' && path) return `Read file ${path}`;
  if (cat === 'sign_in') return e.result === 'denied' ? `Failed sign-in / wrong password on ${e.source_computer || 'LAB-PC01'}` : `Logged on to ${e.source_computer || 'LAB-PC01'}`;
  if (cat === 'sign_out') return `Signed out from ${e.source_computer || 'LAB-PC01'}`;
  if (cat === 'file_copy') {
    const isUsb = /^[D-Z]:/i.test(path);
    return isUsb ? `File pasted / transferred to USB Pen Drive (${path})` : `File copy observed to ${path || 'storage'}`;
  }
  if (cat === 'privilege_change') return `Modified security group privileges (${path || 'Domain Admins'})`;
  if (cat === 'script_block') return `Executed PowerShell script block`;
  if (cat === 'process_start') return `Launched process ${e.process_path || path}`;
  return cat.replaceAll('_', ' ') + (path ? ` (${path})` : '');
}

export function Overview() {
  const { period, bump } = useContext(Context);
  const { data: d, error } = useData('/overview?' + period);

  const onlineCount = d?.presence?.Online || 0;
  const totalDevices = d?.device_count || 1;
  const wefPresence = d?.collectors_summary?.wef?.presence || 'Offline';
  const wefLastSeen = d?.collectors_summary?.wef?.last_seen;
  const epReporting = d?.collectors_summary?.endpoints?.reporting ?? onlineCount;
  const epTotal = d?.collectors_summary?.endpoints?.total ?? totalDevices;
  const dirLastSync = d?.collectors_summary?.directory_sync?.last_sync;

  return (
    <Page
      title="Security overview"
      description="lab.local · Collected telemetry, detection readiness, and active findings"
      action={
        <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
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
          <Link to="/attack-library" className="button">
            Attack Library (17 Topics)
          </Link>
          <Link to="/present" className="button primary">
            Teacher Presentation Mode ➔
          </Link>
        </div>
      }
    >
      <ErrorBox message={error} />
      {d && (
        <>
          {/* Top 4 Metric Cards (Matching Reference 01) */}
          <div className="metrics" style={{ gridTemplateColumns: 'repeat(4, 1fr)', marginBottom: '22px' }}>
            <Link to="/alerts" className="metric clickable-card">
              <div className="metric-icon red"><ShieldAlert size={22} /></div>
              <span>Open alerts</span>
              <strong style={{ color: d.open_alerts > 0 ? '#ef4444' : 'inherit' }}>
                {d.open_alerts}
              </strong>
              <small>Requires human review ➔</small>
            </Link>

            <Link to="/devices" className="metric clickable-card">
              <div className="metric-icon blue"><Monitor size={22} /></div>
              <span>Online devices</span>
              <strong>{onlineCount} / {totalDevices}</strong>
              <small>{d.presence?.Stale || 0} stale · {d.presence?.Offline || 0} offline ➔</small>
            </Link>

            <Link to="/events" className="metric clickable-card">
              <div className="metric-icon teal"><Database size={22} /></div>
              <span>Events collected</span>
              <strong>{d.event_count?.toLocaleString()}</strong>
              <small>Within selected period ➔</small>
            </Link>

            <Link to="/employees" className="metric clickable-card">
              <div className="metric-icon violet"><Users size={22} /></div>
              <span>Employees observed</span>
              <strong>{d.employees_observed ?? 0}</strong>
              <small>From {d.directory_count || 1} directory accounts ➔</small>
            </Link>
          </div>

          {/* Row 1: Event Volume Area Chart + Recent Alert Queue */}
          <div className="grid overview-top">
            <Panel
              title="Event volume"
              subtitle="Persisted events per hour · UTC axis"
              action={<Badge>All events</Badge>}
            >
              <Chart rows={d.volume || []} />
            </Panel>

            <Panel
              title="Recent alert queue"
              subtitle="Rules and behavior-model findings"
              action={<Link to="/alerts" style={{ fontSize: '11px', display: 'flex', alignItems: 'center', gap: '3px' }}>View all <ChevronRight size={13} /></Link>}
            >
              {d.recent_alerts && d.recent_alerts.length > 0 ? (
                <div className="alert-list">
                  {d.recent_alerts.map((a: Data) => (
                    <Link to={'/alerts/' + a.id} className="alert-row" key={a.id}>
                      <Badge tone={a.severity}>{a.severity}</Badge>
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <strong>{a.title}</strong>
                        <small>{a.account || a.user_sid || 'Unknown identity'}</small>
                      </div>
                      <Badge tone={a.status === 'Open' ? 'investigating' : a.status}>
                        {a.status === 'Open' ? 'Needs review' : a.status}
                      </Badge>
                      <ChevronRight size={16} />
                    </Link>
                  ))}
                </div>
              ) : (
                <Empty title="No alerts in this period">
                  Collection is active. No security rules or behavior anomalies triggered.
                </Empty>
              )}
            </Panel>
          </div>

          {/* Row 2: Collection Health + Device Health */}
          <div className="grid two">
            {/* Collection Health Panel */}
            <Panel title="Collection health" subtitle="Measured telemetry ingestion status from collector heartbeats">
              <div className="collection-health-list">
                <div className="col-health-item">
                  <div className="col-health-icon"><Server size={20} /></div>
                  <div className="col-health-info">
                    <strong>Windows Event Forwarding (WEF / DC Bridge)</strong>
                    <small>
                      {wefLastSeen ? `Last seen: ${timeAgo(wefLastSeen)}` : 'Domain controller security log bridge'}
                    </small>
                  </div>
                  <div className="col-health-badge">
                    <span className={`dot ${wefPresence === 'Online' ? 'green' : wefPresence === 'Stale' ? 'amber' : 'red'}`}></span>
                    <span>{wefPresence}</span>
                  </div>
                </div>

                <div className="col-health-item">
                  <div className="col-health-icon"><Monitor size={20} /></div>
                  <div className="col-health-info">
                    <strong>Endpoint agents</strong>
                    <small>
                      {epReporting} of {epTotal} managed device{epTotal === 1 ? '' : 's'} online within 90s threshold
                    </small>
                  </div>
                  <div className="col-health-badge">
                    <span className={`dot ${epReporting > 0 ? 'green' : 'amber'}`}></span>
                    <span>{epReporting} / {epTotal} online</span>
                  </div>
                </div>

                <div className="col-health-item">
                  <div className="col-health-icon"><Database size={20} /></div>
                  <div className="col-health-info">
                    <strong>Directory synchronization</strong>
                    <small>
                      Last successful sync: {dirLastSync ? timeAgo(dirLastSync) : 'Not recorded'}
                    </small>
                  </div>
                  <div className="col-health-badge">
                    <span className={`dot ${dirLastSync ? 'green' : 'amber'}`}></span>
                    <span>{dirLastSync ? 'Synced' : 'Pending'}</span>
                  </div>
                </div>
              </div>
            </Panel>

            {/* Device Health Table Panel */}
            <Panel
              title="Device health"
              subtitle="Measured hardware telemetry from endpoint heartbeats"
              action={
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                  <span className="ai-baseline-tag">
                    <Info size={13} /> AI baseline: {d.uba_state || 'Collecting baseline'}
                  </span>
                  <Link to="/devices" style={{ fontSize: '11px', display: 'flex', alignItems: 'center', gap: '3px' }}>
                    View all <ChevronRight size={13} />
                  </Link>
                </div>
              }
            >
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Device name</th>
                      <th>Status</th>
                      <th>CPU</th>
                      <th>RAM</th>
                      <th>Last seen</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(d.device_health || []).map((v: Data) => {
                      const p = computePresence(v.device?.last_heartbeat);
                      const hasCpu = v.health?.cpu != null;
                      const hasRam = v.health?.ram_percent != null;
                      const dotClass = p === 'Online' ? 'green' : p === 'Stale' ? 'amber' : p === 'Offline' ? 'red' : 'gray';
                      return (
                        <tr key={v.device.id}>
                          <td>
                            <Link to={'/devices/' + v.device.id} style={{ fontWeight: 600 }}>
                              {v.device.hostname}
                            </Link>
                          </td>
                          <td>
                            <span style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
                              <span className={`dot ${dotClass}`}></span>
                              <span>{p}</span>
                            </span>
                          </td>
                          <td style={{ minWidth: '100px' }}>
                            {hasCpu ? (
                              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                <HealthBar percent={v.health.cpu} color="#38bdf8" />
                                <small>{v.health.cpu.toFixed(0)}%</small>
                              </div>
                            ) : (
                              <span style={{ color: 'var(--muted)', fontSize: '12px' }}>—</span>
                            )}
                          </td>
                          <td style={{ minWidth: '100px' }}>
                            {hasRam ? (
                              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                <HealthBar percent={v.health.ram_percent} color="#009b8c" />
                                <small>{v.health.ram_percent.toFixed(0)}%</small>
                              </div>
                            ) : (
                              <span style={{ color: 'var(--muted)', fontSize: '12px' }}>—</span>
                            )}
                          </td>
                          <td>
                            <small>{v.device.last_heartbeat ? timeAgo(v.device.last_heartbeat) : 'Not collected'}</small>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </Panel>
          </div>

          {/* Row 3: MITRE ATT&CK Matrix Grid Widget */}
          <Panel
            title="MITRE ATT&CK® Enterprise Matrix"
            subtitle="Adversary Tactics & Techniques correlated against active enterprise telemetry"
          >
            <MitreMatrix alerts={d.recent_alerts || []} />
          </Panel>

          {/* Row 4: Recent Activity Table */}
          <Panel
            title="Recent activity"
            subtitle="Normalized security actions and access attempts"
            action={<Link to="/events" style={{ fontSize: '11px', display: 'flex', alignItems: 'center', gap: '3px' }}>View all <ChevronRight size={13} /></Link>}
          >
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Employee</th>
                    <th>Action</th>
                    <th>Result</th>
                  </tr>
                </thead>
                <tbody>
                  {(d.recent_events || []).map((e: Data) => (
                    <tr key={e.id}>
                      <td><Time value={e.time} /></td>
                      <td><strong>{e.account || e.user_sid || 'Unknown identity'}</strong></td>
                      <td>{getFriendlyAction(e)}</td>
                      <td>
                        <Badge tone={e.result}>{e.result === 'denied' ? 'Access denied' : (e.result || 'Success')}</Badge>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Panel>
        </>
      )}
    </Page>
  );
}

export function Events() {
  const { period } = useContext(Context);
  const [url] = useSearchParams();
  const initial = Object.fromEntries(url);
  const [filters, setFilters] = useState<Data>(initial);
  const [draft, setDraft] = useState<Data>(initial);
  const [page, setPage] = useState(1);
  const params = period + '&' + new URLSearchParams({ ...filters, page: String(page) });
  const { data, error } = useData('/events?' + params);

  return (
    <Page
      title="Event Explorer"
      description="Search normalized activity, then inspect the original source evidence."
      action={
        <div className="actions">
          <a className="button" href={'/api/export/events?format=csv&' + params}><Download size={15} />CSV</a>
          <a className="button" href={'/api/export/events?format=json&' + params}>JSON</a>
        </div>
      }
    >
      <form
        className="filters"
        onSubmit={e => {
          e.preventDefault();
          setFilters(draft);
          setPage(1);
        }}
      >
        {[
          ['q', 'Search identity, source or path'],
          ['user_sid', 'Employee SID'],
          ['device_id', 'Device ID'],
          ['event_id', 'Event ID'],
          ['provider', 'Provider'],
          ['channel', 'Channel'],
          ['category', 'Category'],
          ['path', 'Object path']
        ].map(([k, p]) => (
          <input key={k} aria-label={p} placeholder={p} value={draft[k] || ''} onChange={e => setDraft({ ...draft, [k]: e.target.value })} />
        ))}
        <select aria-label="Outcome" value={draft.result || ''} onChange={e => setDraft({ ...draft, result: e.target.value })}>
          <option value="">All outcomes</option>
          {['success', 'denied', 'observed', 'unknown'].map(s => <option key={s}>{s}</option>)}
        </select>
        <select aria-label="Related alert severity" value={draft.severity || ''} onChange={e => setDraft({ ...draft, severity: e.target.value })}>
          <option value="">Related alert severity</option>
          {['High', 'Medium', 'Low'].map(s => <option key={s}>{s}</option>)}
        </select>
        <button className="primary">Search</button>
        <button type="button" onClick={() => { setFilters({}); setDraft({}); setPage(1); }}>Clear</button>
      </form>
      <ErrorBox message={error} />
      {data && (
        <Panel title="Source events" subtitle="Event outcomes and alert severity are distinct">
          <EventTable items={data.items} />
          <Pager data={data} page={page} setPage={setPage} />
        </Panel>
      )}
    </Page>
  );
}

export function EventDetail() {
  const { id } = useParams();
  const { data: d, error } = useData('/events/' + id);

  return (
    <Page title="Source evidence" description="Normalized context alongside the unchanged source record." action={<Link className="button" to="/events">Back to Explorer</Link>}>
      <ErrorBox message={error} />
      {d && (
        <>
          <Panel title={d.category.replaceAll('_', ' ')} action={<Badge tone={d.result}>{d.result}</Badge>}>
            <Facts
              items={[
                ["Event time", <Time value={d.time} />],
                ["Received", <Time value={d.received_at} />],
                ["Original computer", d.source_computer],
                ["Collector", d.collector_id],
                ["Employee", d.account || d.user_sid],
                ["Access device", d.access_device_id],
                ["Attribution", d.attribution],
                ["Source address", d.source_address],
                ["Path", d.object_path],
                ["Evidence type", d.evidence_type],
                ["Provider / channel", d.provider + ' / ' + d.channel],
                ["Source record", d.source_record]
              ]}
            />
          </Panel>
          <div className="grid two">
            <Panel title="Structured source fields" subtitle="Parsed telemetry attributes">
              {d.fields && typeof d.fields === 'object' && Object.keys(d.fields).length > 0 ? (
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th style={{ width: '38%' }}>Property</th>
                        <th>Observed value</th>
                      </tr>
                    </thead>
                    <tbody>
                      {Object.entries(d.fields).map(([k, val]) => (
                        <tr key={k}>
                          <td style={{ fontWeight: 600, color: 'var(--text)' }}>
                            {k.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())}
                          </td>
                          <td>
                            {typeof val === 'boolean' ? (
                              <Badge tone={val ? 'high' : 'low'}>{val ? 'True' : 'False'}</Badge>
                            ) : typeof val === 'object' && val !== null ? (
                              <pre style={{ margin: 0, fontSize: '11px', fontFamily: 'Consolas, monospace' }}>{JSON.stringify(val, null, 2)}</pre>
                            ) : (
                              <span style={{ fontFamily: 'Consolas, monospace', fontSize: '11.5px', wordBreak: 'break-all' }}>{String(val)}</span>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <Empty title="No structured fields recorded for this event" />
              )}
              <details style={{ marginTop: '16px', padding: '10px 0 0', borderTop: '1px solid var(--border)' }}>
                <summary style={{ cursor: 'pointer', color: 'var(--blue)', fontSize: '11px', fontWeight: 600 }}>
                  Technical details (Raw JSON)
                </summary>
                <Json value={d.fields} />
              </details>
            </Panel>

            <Panel title="Original evidence" subtitle={d.raw_state || 'Retained'}>
              <div style={{ padding: '16px 20px', display: 'flex', flexDirection: 'column', gap: '10px', fontSize: '12px' }}>
                <div><span style={{ color: 'var(--muted)', display: 'block', fontSize: '10px', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Source Record ID</span><span style={{ fontFamily: 'Consolas, monospace', fontSize: '11px' }}>{d.source_record || d.id}</span></div>
                <div><span style={{ color: 'var(--muted)', display: 'block', fontSize: '10px', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Evidence Kind</span><span>{d.evidence_type || 'Windows security event'}</span></div>
                <div><span style={{ color: 'var(--muted)', display: 'block', fontSize: '10px', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Retention Status</span><span>{d.raw_state || 'Retained under standard retention policy'}</span></div>
              </div>
              <details style={{ margin: '0 20px 16px', padding: '10px 0 0', borderTop: '1px solid var(--border)' }}>
                <summary style={{ cursor: 'pointer', color: 'var(--blue)', fontSize: '11px', fontWeight: 600 }}>
                  Technical source record ({typeof d.raw === 'string' && d.raw.startsWith('<') ? 'XML' : 'JSON'})
                </summary>
                <Json value={d.raw || 'Raw evidence expired under the configured policy.'} />
              </details>
            </Panel>
          </div>

          {(d.process_path || d.command_line) && (
            <Panel title="Process context" subtitle="Commands are displayed as evidence and never executed">
              <div style={{ padding: '16px 20px' }}>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '16px', marginBottom: '14px' }}>
                  <div>
                    <small style={{ color: 'var(--muted)', display: 'block', textTransform: 'uppercase', fontSize: '10px', letterSpacing: '0.5px' }}>Process executable</small>
                    <code style={{ fontSize: '12px', background: 'var(--surface2)', padding: '3px 6px', borderRadius: '4px' }}>{d.process_path || '—'}</code>
                  </div>
                  <div>
                    <small style={{ color: 'var(--muted)', display: 'block', textTransform: 'uppercase', fontSize: '10px', letterSpacing: '0.5px' }}>Process ID / Parent</small>
                    <span style={{ fontSize: '12px' }}>PID: {d.process_id || '—'} {d.parent_id ? `(Parent: ${d.parent_id})` : ''}</span>
                  </div>
                </div>
                {d.command_line && (
                  <div style={{ marginBottom: '14px' }}>
                    <small style={{ color: 'var(--muted)', display: 'block', marginBottom: '4px', textTransform: 'uppercase', fontSize: '10px', letterSpacing: '0.5px' }}>Observed command line</small>
                    <div style={{ background: 'var(--surface2)', border: '1px solid var(--border)', borderRadius: '6px', padding: '10px 14px', fontFamily: 'Consolas, monospace', fontSize: '11.5px', wordBreak: 'break-all', color: 'var(--text)' }}>
                      {d.command_line}
                    </div>
                  </div>
                )}
                <details style={{ marginTop: '12px', padding: '10px 0 0', borderTop: '1px solid var(--border)' }}>
                  <summary style={{ cursor: 'pointer', color: 'var(--blue)', fontSize: '11px', fontWeight: 600 }}>
                    Technical process lineage (Raw JSON)
                  </summary>
                  <Json value={{ process: d.process_path, pid: d.process_id, guid: d.process_guid, parent: d.parent_id, command: d.command_line, lineage: d.process_lineage }} />
                </details>
              </div>
            </Panel>
          )}
          <Panel title="Related session activity" subtitle="Same source computer and logon ID within ±15 minutes; verify SID and session boundaries">
            <EventTable items={d.related} />
          </Panel>
          <Panel title="Linked findings">
            <AlertList items={d.alerts} />
          </Panel>
        </>
      )}
    </Page>
  );
}
