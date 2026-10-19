import { useState, useEffect, useContext, useMemo } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import {
  Globe, Download, Database, FileText, ExternalLink, Info, X
} from 'lucide-react';
import { Context, api, Badge, Empty, ErrorBox, Json, Time } from './core';
import type { Data } from './core';

function formatBytesHuman(bytes?: number | null): string {
  if (bytes == null || Number.isNaN(Number(bytes))) return '0 B';
  const n = Number(bytes);
  if (n < 1024) return `${n} B`;
  const kib = n / 1024;
  if (kib < 1024) return `${kib >= 10 ? kib.toFixed(0) : kib.toFixed(1)} KiB`;
  const mib = kib / 1024;
  if (mib < 1024) return `${mib.toFixed(1)} MiB`;
  return `${(mib / 1024).toFixed(2)} GiB`;
}

function formatAgoShort(iso?: string | null): string {
  if (!iso) return 'Not received';
  const sec = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000));
  if (sec < 60) return `${sec} sec ago`;
  if (sec < 3600) return `${Math.floor(sec / 60)} min ago`;
  if (sec < 86400) return `${Math.floor(sec / 3600)} hr ago`;
  return `${Math.floor(sec / 86400)} d ago`;
}

function shortDownloadPath(p?: string | null, fallbackName?: string): string {
  if (!p) return fallbackName ? `Downloads\\${fallbackName}` : 'Unavailable';
  const idx = p.toLowerCase().indexOf('downloads\\');
  if (idx >= 0) return p.slice(idx);
  return p;
}

export function BrowserActivity() {
  const { period, refresh: globalRefresh } = useContext(Context);
  const [searchParams] = useSearchParams();

  const [devices, setDevices] = useState<Data[]>([]);
  const [selectedDevice, setSelectedDevice] = useState<string>(searchParams.get('device_id') || '');
  const [selectedAccount, setSelectedAccount] = useState<string>(searchParams.get('user_sid') || '');
  const [selectedBrowser, setSelectedBrowser] = useState<string>(searchParams.get('browser_name') || '');
  const [domainFilter, setDomainFilter] = useState<string>(searchParams.get('q') || '');
  const [activeTab, setActiveTab] = useState<'downloads' | 'visits' | 'health'>(
    (searchParams.get('tab') as 'downloads' | 'visits' | 'health') || 'downloads'
  );

  const [overview, setOverview] = useState<Data | null>(null);
  const [navData, setNavData] = useState<Data | null>(null);
  const [dlData, setDlData] = useState<Data | null>(null);
  const [selectedDlId, setSelectedDlId] = useState<string>(searchParams.get('download_id') || '');
  const [dlDetail, setDlDetail] = useState<Data | null>(null);
  const [error, setError] = useState<string>('');

  useEffect(() => {
    api('/devices')
      .then(res => setDevices(res.items || []))
      .catch(() => {});
  }, []);

  useEffect(() => {
    let live = true;
    const loadBrowserData = async () => {
      try {
        const qs = new URLSearchParams(period);
        if (selectedDevice) qs.set('device_id', selectedDevice);
        if (selectedAccount) qs.set('user_sid', selectedAccount);
        if (domainFilter.trim()) qs.set('q', domainFilter.trim());

        const [ovRes, navRes, dlRes] = await Promise.all([
          api(`/browser/overview?${qs.toString()}`),
          api(`/browser/navigations?${qs.toString()}&page_size=50`),
          api(`/browser/downloads?${qs.toString()}&page_size=50`)
        ]);
        if (!live) return;
        setOverview(ovRes);
        setNavData(navRes);
        setDlData(dlRes);
        setError('');

        const dlItems: Data[] = dlRes.items || [];
        if (dlItems.length > 0) {
          const exists = dlItems.some(d => d.id === selectedDlId);
          if (!selectedDlId || !exists) {
            setSelectedDlId(dlItems[0].id);
          }
        } else {
          setSelectedDlId('');
        }
      } catch (e: any) {
        if (live) setError(e.message || 'Failed to load browser telemetry');
      }
    };

    loadBrowserData();
    const timer = setInterval(loadBrowserData, 15000);
    return () => {
      live = false;
      clearInterval(timer);
    };
  }, [selectedDevice, selectedAccount, selectedBrowser, domainFilter, period, globalRefresh]);

  useEffect(() => {
    if (!selectedDlId) {
      setDlDetail(null);
      return;
    }
    let live = true;
    api(`/browser/downloads/${encodeURIComponent(selectedDlId)}`)
      .then(d => {
        if (live) setDlDetail(d);
      })
      .catch(() => {
        if (live) setDlDetail(null);
      });
    return () => {
      live = false;
    };
  }, [selectedDlId, dlData]);

  const profiles: Data[] = overview?.profiles || [];
  const gaps: Data[] = overview?.gaps || overview?.collection_gaps || [];
  const topDomains: Data[] = overview?.domain_breakdown || overview?.top_domains || [];
  const summary: Data = overview?.summary || {};
  const allDownloads: Data[] = dlData?.items || [];
  const allNavigations: Data[] = navData?.items || [];

  const downloads = useMemo(() => {
    if (!selectedBrowser) return allDownloads;
    const bLower = selectedBrowser.toLowerCase();
    return allDownloads.filter(d => (d.browser_name || '').toLowerCase().includes(bLower));
  }, [allDownloads, selectedBrowser]);

  const navigations = useMemo(() => {
    if (!selectedBrowser) return allNavigations;
    const bLower = selectedBrowser.toLowerCase();
    return allNavigations.filter(n => (n.browser_name || '').toLowerCase().includes(bLower));
  }, [allNavigations, selectedBrowser]);

  const distinctAccounts = useMemo(() => {
    const map = new Map<string, string>();
    for (const p of profiles) {
      if (p.user_sid) map.set(p.user_sid, p.account || p.user_sid);
    }
    for (const d of allDownloads) {
      if (d.user_sid) map.set(d.user_sid, d.account || d.user_sid);
    }
    for (const n of allNavigations) {
      if (n.user_sid) map.set(n.user_sid, n.account || n.user_sid);
    }
    return Array.from(map.entries());
  }, [profiles, allDownloads, allNavigations]);

  const statusBanner = useMemo(() => {
    if (profiles.length === 0) {
      return {
        tone: 'offline',
        dot: 'gray',
        title: 'No enrolled browser profile reporting',
        lastSeen: 'Not received'
      };
    }
    const latestProfile = profiles[0];
    const st = (latestProfile.status || 'active').toLowerCase();
    const isPaused = st === 'paused';
    return {
      tone: isPaused ? 'paused' : 'active',
      dot: isPaused ? 'amber' : 'green',
      title: isPaused ? 'Extension collection paused' : 'Extension connected',
      lastSeen: formatAgoShort(latestProfile.last_seen_at || latestProfile.enrolled_at)
    };
  }, [profiles]);

  const selectedDownload =
    dlDetail?.download || (dlDetail?.id ? dlDetail : null) || downloads.find(d => d.id === selectedDlId) || null;
  const selectedCorrelations: Data[] =
    dlDetail?.correlations || selectedDownload?.correlations || [];
  const selectedCaseKey =
    selectedDownload?.case_key ||
    (selectedCorrelations.length > 0 ? selectedCorrelations[0].case_key : null);

  return (
    <div className="pm-page">
      <div className="pm-header-row">
        <div>
          <h1>Browser activity</h1>
          <p>Website navigation and download metadata from enrolled lab profiles</p>
        </div>
      </div>

      <ErrorBox message={error} />

      {/* 4-Column Filter Bar */}
      <div className="ba-filter-grid">
        <label className="pm-filter-item">
          <span>Device</span>
          <select
            aria-label="Filter by device"
            value={selectedDevice}
            onChange={e => setSelectedDevice(e.target.value)}
          >
            <option value="">All enrolled devices</option>
            {devices.map(d => (
              <option key={d.id} value={d.id}>
                {d.hostname}
              </option>
            ))}
          </select>
        </label>

        <label className="pm-filter-item">
          <span>Account</span>
          <select
            aria-label="Filter by account"
            value={selectedAccount}
            onChange={e => setSelectedAccount(e.target.value)}
          >
            <option value="">All observed accounts</option>
            {distinctAccounts.map(([sid, label]) => (
              <option key={sid} value={sid}>
                {label}
              </option>
            ))}
          </select>
        </label>

        <label className="pm-filter-item">
          <span>Browser</span>
          <select
            aria-label="Filter by browser"
            value={selectedBrowser}
            onChange={e => setSelectedBrowser(e.target.value)}
          >
            <option value="">All browsers</option>
            <option value="Chrome">Chrome</option>
            <option value="Edge">Edge</option>
          </select>
        </label>

        <label className="pm-filter-item">
          <span>Search domain or file</span>
          <input
            type="search"
            placeholder="e.g. training.lab.local or .ps1"
            value={domainFilter}
            onChange={e => setDomainFilter(e.target.value)}
          />
        </label>
      </div>

      {/* Status Strip */}
      <div className={`ba-status-strip ${statusBanner.tone}`}>
        <span className="pm-status-indicator">
          <span className={`dot ${statusBanner.dot}`} />
          <strong>{statusBanner.title}</strong>
        </span>
        <span className="pm-divider">|</span>
        <span>Last received {statusBanner.lastSeen}</span>
        <span className="pm-divider">|</span>
        <span>Scope: enrolled profile only</span>
      </div>

      {/* 3 KPI Summary Cards */}
      <div className="pm-kpi-grid">
        <div className="pm-kpi-card">
          <div className="pm-kpi-icon teal">
            <Globe size={22} />
          </div>
          <div className="pm-kpi-body">
            <span className="pm-kpi-label">Navigations recorded</span>
            <strong className="pm-kpi-value">
              {summary.top_level_visits ?? summary.navigations_count ?? navigations.length}
            </strong>
            <small className="muted">
              {summary.unique_domains ?? 0} unique top-level domain(s)
            </small>
          </div>
        </div>

        <div className="pm-kpi-card">
          <div className="pm-kpi-icon teal">
            <Download size={22} />
          </div>
          <div className="pm-kpi-body">
            <span className="pm-kpi-label">Completed downloads</span>
            <strong className="pm-kpi-value">
              {summary.completed_downloads ?? summary.completed_downloads_count ?? 0}
            </strong>
            <small className="muted">
              {summary.downloads_with_followup ?? 0} with correlated process activity
            </small>
          </div>
        </div>

        <div className="pm-kpi-card">
          <div className="pm-kpi-icon teal">
            <Database size={22} />
          </div>
          <div className="pm-kpi-body">
            <span className="pm-kpi-label">Downloaded bytes</span>
            <strong className="pm-kpi-value">
              {formatBytesHuman(summary.completed_download_bytes ?? 0)}
            </strong>
            <small className="muted">Deduplicated across download state revisions</small>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="pm-tabs-header" style={{ marginBottom: '16px' }}>
        <button
          type="button"
          className={`pm-tab-item ${activeTab === 'visits' ? 'active' : ''}`}
          onClick={() => setActiveTab('visits')}
        >
          Website visits
        </button>
        <button
          type="button"
          className={`pm-tab-item ${activeTab === 'downloads' ? 'active' : ''}`}
          onClick={() => setActiveTab('downloads')}
        >
          Downloads
        </button>
        <button
          type="button"
          className={`pm-tab-item ${activeTab === 'health' ? 'active' : ''}`}
          onClick={() => setActiveTab('health')}
        >
          Collection health
        </button>
      </div>

      {activeTab === 'downloads' && (
        <>
          <div className="ba-downloads-split">
            <div className="panel" style={{ marginBottom: 0 }}>
              {downloads.length === 0 ? (
                <Empty title="No browser downloads recorded in this period">
                  Downloads from enrolled Chrome or Edge profiles appear here with revision history and follow-up execution links.
                </Empty>
              ) : (
                <div className="table-wrap">
                  <table className="pm-table">
                    <thead>
                      <tr>
                        <th>Time</th>
                        <th>File</th>
                        <th>Source domain</th>
                        <th>Size</th>
                        <th>Status</th>
                        <th>Review</th>
                      </tr>
                    </thead>
                    <tbody>
                      {downloads.map(dl => {
                        const isSelected = dl.id === selectedDlId;
                        const hasExec =
                          Boolean(dl.case_key) ||
                          (dl.followup_processes && dl.followup_processes.length > 0) ||
                          (dl.correlations && dl.correlations.length > 0);
                        const isDone = dl.state === 'completed' || dl.state === 'complete';
                        const statusLabel = isDone
                          ? 'Completed'
                          : dl.state === 'interrupted'
                          ? 'Interrupted'
                          : 'In progress';
                        const ts = dl.completed_at || dl.end_time || dl.started_at || dl.start_time;
                        return (
                          <tr
                            key={dl.id}
                            className={isSelected ? 'pm-row-selected' : ''}
                            onClick={() => setSelectedDlId(dl.id)}
                            style={{ cursor: 'pointer' }}
                          >
                            <td>
                              {ts
                                ? new Date(ts).toLocaleTimeString([], {
                                    hour: '2-digit',
                                    minute: '2-digit'
                                  })
                                : '—'}
                            </td>
                            <td>
                              <strong>{dl.filename}</strong>
                            </td>
                            <td>{dl.source_domain || 'unknown'}</td>
                            <td>
                              {formatBytesHuman(
                                dl.final_size_bytes ?? dl.total_bytes ?? dl.bytes_received
                              )}
                            </td>
                            <td>
                              <span className="pm-state-cell">
                                <span
                                  className={`dot ${
                                    isDone
                                      ? 'green'
                                      : dl.state === 'interrupted'
                                      ? 'red'
                                      : 'amber'
                                  }`}
                                />
                                {statusLabel}
                              </span>
                            </td>
                            <td>
                              {hasExec ? (
                                <Link
                                  to={
                                    dl.case_key
                                      ? `/timeline?case_key=${encodeURIComponent(dl.case_key)}`
                                      : `/timeline?q=${encodeURIComponent(dl.filename || '')}`
                                  }
                                  style={{ fontWeight: 600 }}
                                  onClick={e => e.stopPropagation()}
                                >
                                  Review execution
                                </Link>
                              ) : (
                                <button
                                  type="button"
                                  className="pm-link-btn"
                                  onClick={e => {
                                    e.stopPropagation();
                                    setSelectedDlId(dl.id);
                                  }}
                                >
                                  Open details
                                </button>
                              )}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            {/* Selected Download Card */}
            {selectedDownload && (
              <aside className="panel ba-detail-card" style={{ marginBottom: 0 }}>
                <div className="ba-detail-header">
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    <FileText size={20} style={{ color: '#2563eb' }} />
                    <h3 style={{ margin: 0 }}>{selectedDownload.filename}</h3>
                  </div>
                  <button
                    type="button"
                    className="icon-button"
                    aria-label="Close download details"
                    onClick={() => setSelectedDlId('')}
                  >
                    <X size={16} />
                  </button>
                </div>

                <div className="pm-kv-table">
                  <div className="pm-kv-row">
                    <span>Saved path:</span>
                    <strong title={selectedDownload.final_path || selectedDownload.target_path || ''}>
                      {shortDownloadPath(
                        selectedDownload.final_path || selectedDownload.target_path,
                        selectedDownload.filename
                      )}
                    </strong>
                  </div>
                  <div className="pm-kv-row">
                    <span>Windows user:</span>
                    <strong>{selectedDownload.account || selectedDownload.user_sid || 'Unknown'}</strong>
                  </div>
                  <div className="pm-kv-row">
                    <span>Source:</span>
                    <strong>Browser extension ({selectedDownload.browser_name || 'Chrome'})</strong>
                  </div>
                  <div className="pm-kv-row">
                    <span>Revisions:</span>
                    <strong>
                      {dlDetail?.revisions?.length || selectedDownload.revision_count || 1} state update(s)
                    </strong>
                  </div>
                  {selectedDownload.sha256 && (
                    <div className="pm-kv-row">
                      <span>SHA-256:</span>
                      <code style={{ fontSize: '10.5px', wordBreak: 'break-all' }}>
                        {selectedDownload.sha256}
                      </code>
                    </div>
                  )}
                  <div className="pm-kv-row">
                    <span>Execution:</span>
                    <strong>
                      {selectedCorrelations.length > 0 || selectedCaseKey
                        ? 'Related event available'
                        : 'No follow-up execution observed'}
                    </strong>
                  </div>
                </div>

                <Link
                  to={
                    selectedCaseKey
                      ? `/timeline?case_key=${encodeURIComponent(selectedCaseKey)}`
                      : `/timeline?q=${encodeURIComponent(selectedDownload.filename || '')}`
                  }
                  className="button primary"
                  style={{ width: '100%', marginTop: '14px', justifyContent: 'center' }}
                >
                  <ExternalLink size={15} /> Open investigation timeline
                </Link>

                <details style={{ marginTop: '12px' }}>
                  <summary>Revision history &amp; correlation evidence</summary>
                  <Json value={dlDetail || selectedDownload} />
                </details>
              </aside>
            )}
          </div>

          {/* Recent Website Navigations Table */}
          <div className="panel" style={{ marginTop: '20px' }}>
            <div className="panel-head">
              <div>
                <h2>Recent website navigations</h2>
                <p>Top-level domain navigations recorded from enrolled browser profiles</p>
              </div>
            </div>
            {navigations.length === 0 ? (
              <Empty title="No domain navigations recorded in this period" />
            ) : (
              <div className="table-wrap">
                <table className="pm-table">
                  <thead>
                    <tr>
                      <th>Time</th>
                      <th>Domain</th>
                      <th>Browser</th>
                      <th>Device</th>
                      <th>Windows user</th>
                    </tr>
                  </thead>
                  <tbody>
                    {navigations.slice(0, 15).map(nav => (
                      <tr key={nav.id}>
                        <td>
                          {nav.navigation_time
                            ? new Date(nav.navigation_time).toLocaleTimeString([], {
                                hour: '2-digit',
                                minute: '2-digit'
                              })
                            : '—'}
                        </td>
                        <td>
                          <strong>{nav.normalized_domain || nav.domain}</strong>
                        </td>
                        <td>{nav.browser_name || 'Chrome'}</td>
                        <td>{nav.hostname || nav.device_id || 'Unknown'}</td>
                        <td>{nav.account || nav.user_sid || 'Unknown'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </>
      )}

      {activeTab === 'visits' && (
        <div className="grid two">
          <div className="panel">
            <div className="panel-head">
              <div>
                <h2>Domain breakdown</h2>
                <p>Aggregated top-level HTTP/HTTPS domain visits in selected period</p>
              </div>
            </div>
            {topDomains.length === 0 ? (
              <Empty title="No domain visits aggregated" />
            ) : (
              <div className="table-wrap">
                <table className="pm-table">
                  <thead>
                    <tr>
                      <th>Domain</th>
                      <th>Visits</th>
                      <th>Downloads</th>
                      <th>Last visit</th>
                    </tr>
                  </thead>
                  <tbody>
                    {topDomains.map(d => {
                      const domName = d.normalized_domain || d.domain;
                      return (
                        <tr key={domName}>
                          <td>
                            <strong>{domName}</strong>
                            {d.policy_match && (
                              <Badge tone="medium">Policy review</Badge>
                            )}
                          </td>
                          <td>{d.visit_count}</td>
                          <td>{d.downloads_from_domain ?? 0}</td>
                          <td>
                            <Time value={d.last_seen || d.last_visit_at} />
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          <div className="panel">
            <div className="panel-head">
              <div>
                <h2>All recent navigations</h2>
                <p>Chronological top-level frame navigations</p>
              </div>
            </div>
            {navigations.length === 0 ? (
              <Empty title="No navigations in this period" />
            ) : (
              <div className="table-wrap">
                <table className="pm-table">
                  <thead>
                    <tr>
                      <th>Time</th>
                      <th>Domain</th>
                      <th>Transition</th>
                      <th>User</th>
                    </tr>
                  </thead>
                  <tbody>
                    {navigations.map(nav => (
                      <tr key={nav.id}>
                        <td>
                          <Time value={nav.navigation_time} />
                        </td>
                        <td>
                          <strong>{nav.normalized_domain || nav.domain}</strong>
                        </td>
                        <td>{nav.transition_type || 'link'}</td>
                        <td>{nav.account || nav.user_sid || 'Unknown'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {activeTab === 'health' && (
        <div className="grid two">
          <div className="panel">
            <div className="panel-head">
              <div>
                <h2>Enrolled browser profiles</h2>
                <p>Browser extension profiles bound to Windows OS user SIDs via Native Messaging</p>
              </div>
            </div>
            {profiles.length === 0 ? (
              <Empty title="No enrolled browser profiles">
                Install the MV3 extension and run install_native_host.ps1 on LAB-PC01 to bind a work browser profile.
              </Empty>
            ) : (
              <div className="table-wrap">
                <table className="pm-table">
                  <thead>
                    <tr>
                      <th>Profile ID</th>
                      <th>Browser</th>
                      <th>Windows user</th>
                      <th>Device</th>
                      <th>Status</th>
                      <th>Last seen</th>
                    </tr>
                  </thead>
                  <tbody>
                    {profiles.map(p => (
                      <tr key={p.profile_id}>
                        <td>
                          <code>{p.profile_id}</code>
                          <small>{p.profile_label}</small>
                        </td>
                        <td>
                          {p.browser_name} {p.browser_version}
                        </td>
                        <td>
                          <strong>{p.account || 'Unknown'}</strong>
                          <small>{p.user_sid}</small>
                        </td>
                        <td>{p.hostname || p.device_id}</td>
                        <td>
                          <Badge tone={p.status === 'active' || p.status === 'Active' ? 'online' : 'stale'}>
                            {p.status}
                          </Badge>
                        </td>
                        <td>
                          <Time value={p.last_seen_at} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          <div className="panel">
            <div className="panel-head">
              <div>
                <h2>Collection gaps &amp; pause log</h2>
                <p>Explicitly recorded telemetry pauses, disconnects, and trust boundaries</p>
              </div>
            </div>
            {gaps.length === 0 ? (
              <Empty title="No collection gaps recorded">
                Pausing the extension or disconnecting the native bridge records an explicit audit gap here.
              </Empty>
            ) : (
              <div className="table-wrap">
                <table className="pm-table">
                  <thead>
                    <tr>
                      <th>Started</th>
                      <th>Ended</th>
                      <th>Kind</th>
                      <th>Reason</th>
                    </tr>
                  </thead>
                  <tbody>
                    {gaps.map((g: Data, i: number) => (
                      <tr key={g.id || i}>
                        <td>
                          <Time value={g.started_at || g.gap_start} />
                        </td>
                        <td>
                          {g.ended_at || g.gap_end ? (
                            <Time value={g.ended_at || g.gap_end} />
                          ) : (
                            'Ongoing'
                          )}
                        </td>
                        <td>
                          <Badge tone="stale">{g.gap_kind || g.status || 'paused'}</Badge>
                        </td>
                        <td>{g.reason || 'Collection paused'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Privacy & Scope Footer Banner */}
      <div className="ba-privacy-banner">
        <Info size={16} />
        <div>
          <strong>
            Domains and download metadata only • No passwords, cookies, page contents or private browsing.
          </strong>
          <div>A recorded visit does not prove attention or intent.</div>
        </div>
      </div>
    </div>
  );
}
