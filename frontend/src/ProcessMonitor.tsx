import { useState, useEffect, useContext, useMemo } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import {
  Cpu, HardDrive, ClipboardList, Search, Terminal, Globe, Folder, Settings,
  Shield, FileCode, Info, ArrowRight, ChevronRight, AlertTriangle, GitBranch
} from 'lucide-react';
import { Context, api, Badge, Empty, ErrorBox, Json, Time } from './core';
import type { Data } from './core';

function formatMiB(bytes?: number | null): string {
  if (bytes == null || Number.isNaN(Number(bytes))) return 'Unavailable';
  const mib = Number(bytes) / (1024 * 1024);
  if (mib >= 1024) return `${(mib / 1024).toFixed(2)} GiB`;
  if (mib >= 10) return `${mib.toFixed(0)} MiB`;
  return `${mib.toFixed(1)} MiB`;
}

function formatGiBFromBytes(bytes?: number | null): string {
  if (bytes == null || Number.isNaN(Number(bytes))) return '—';
  return (Number(bytes) / (1024 * 1024 * 1024)).toFixed(2);
}

function formatAgeSeconds(iso?: string | null): string {
  if (!iso) return 'Unavailable';
  const diffSec = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000));
  if (diffSec < 60) return `${diffSec} sec`;
  if (diffSec < 3600) return `${Math.floor(diffSec / 60)} min ${diffSec % 60} sec`;
  return `${Math.floor(diffSec / 3600)} hr`;
}

function ProcessIcon({ name, size = 18 }: { name?: string; size?: number }) {
  const n = (name || '').toLowerCase();
  if (n.includes('powershell') || n.includes('pwsh') || n === 'cmd.exe' || n.includes('conhost')) {
    return (
      <span className="proc-icon-badge blue">
        <Terminal size={size} />
      </span>
    );
  }
  if (n.includes('chrome') || n.includes('msedge') || n.includes('firefox')) {
    return (
      <span className="proc-icon-badge teal">
        <Globe size={size} />
      </span>
    );
  }
  if (n.includes('explorer')) {
    return (
      <span className="proc-icon-badge amber">
        <Folder size={size} />
      </span>
    );
  }
  if (n.includes('msmpeng') || n.includes('defender') || n.includes('securityhealth')) {
    return (
      <span className="proc-icon-badge green">
        <Shield size={size} />
      </span>
    );
  }
  if (n.includes('svchost') || n.includes('services') || n.includes('lsass') || n.includes('system')) {
    return (
      <span className="proc-icon-badge slate">
        <Settings size={size} />
      </span>
    );
  }
  return (
    <span className="proc-icon-badge violet">
      <FileCode size={size} />
    </span>
  );
}

export function ProcessMonitor() {
  const { period, refresh: globalRefresh } = useContext(Context);
  const [searchParams, setSearchParams] = useSearchParams();

  const [devices, setDevices] = useState<Data[]>([]);
  const [selectedDevice, setSelectedDevice] = useState<string>(searchParams.get('device_id') || '');
  const [activeTab, setActiveTab] = useState<'apps' | 'live' | 'history' | 'tree'>(
    (searchParams.get('tab') as 'apps' | 'live' | 'history' | 'tree') || 'live'
  );
  const [refreshSec, setRefreshSec] = useState<number>(15);
  const [searchQuery, setSearchQuery] = useState<string>(searchParams.get('q') || '');

  const [procData, setProcData] = useState<Data | null>(null);
  const [historyData, setHistoryData] = useState<Data | null>(null);
  const [treeData, setTreeData] = useState<Data | null>(null);
  const [selectedKey, setSelectedKey] = useState<string>(
    searchParams.get('instance_key') || searchParams.get('process_key') || ''
  );
  const [detailData, setDetailData] = useState<Data | null>(null);
  const [error, setError] = useState<string>('');

  useEffect(() => {
    api('/devices')
      .then(res => {
        const list = res.items || [];
        setDevices(list);
        if (!selectedDevice && list.length > 0) {
          const preferred = list.find((d: Data) => /lab-pc01/i.test(d.hostname || '')) || list[0];
          setSelectedDevice(preferred.id);
        }
      })
      .catch(e => setError(e.message));
  }, []);

  useEffect(() => {
    let live = true;
    const loadAll = async () => {
      try {
        const qs = new URLSearchParams(period);
        if (selectedDevice) qs.set('device_id', selectedDevice);
        qs.set('mode', activeTab === 'history' ? 'history' : 'live');
        qs.set('page_size', '100');
        if (searchQuery.trim()) qs.set('q', searchQuery.trim());

        const qsPage2 = new URLSearchParams(qs);
        qsPage2.set('page', '2');

        const [pRes1, pRes2, hRes, tRes] = await Promise.all([
          api(`/processes?${qs.toString()}`),
          api(`/processes?${qsPage2.toString()}`).catch(() => ({ items: [] })),
          api(`/processes/history?${qs.toString()}&page_size=50`),
          api(`/processes/tree?${qs.toString()}`)
        ]);
        if (!live) return;
        const combinedItems: Data[] = [...(pRes1.items || []), ...(pRes2.items || [])];
        const mergedRes = { ...pRes1, items: combinedItems };
        setProcData(mergedRes);
        setHistoryData(hRes);
        setTreeData(tRes);
        setError('');

        if (combinedItems.length > 0) {
          const currentExists = combinedItems.some((x: Data) => (x.instance_key || x.process_key) === selectedKey);
          if (!selectedKey || !currentExists) {
            setSelectedKey(combinedItems[0].instance_key || combinedItems[0].process_key);
          }
        }
      } catch (e: any) {
        if (live) setError(e.message || 'Failed to load process telemetry');
      }
    };

    loadAll();
    if (refreshSec > 0) {
      const timer = setInterval(loadAll, refreshSec * 1000);
      return () => {
        live = false;
        clearInterval(timer);
      };
    }
    return () => {
      live = false;
    };
  }, [selectedDevice, activeTab, searchQuery, period, refreshSec, globalRefresh]);

  useEffect(() => {
    if (!selectedKey) {
      setDetailData(null);
      return;
    }
    let live = true;
    api(`/processes/${encodeURIComponent(selectedKey)}`)
      .then(d => {
        if (live) setDetailData(d);
      })
      .catch(() => {
        if (live) setDetailData(null);
      });
    return () => {
      live = false;
    };
  }, [selectedKey, procData]);

  const currentDeviceObj = useMemo(
    () => devices.find(d => d.id === selectedDevice) || null,
    [devices, selectedDevice]
  );

  const latestSnapshot = procData?.latest_snapshot || null;

  const { items, runningApps } = useMemo(() => {
    const rawItems: Data[] = procData?.items || [];
    const appCatalog: Record<string, string> = {
      'msedge.exe': 'Microsoft Edge',
      'chrome.exe': 'Google Chrome',
      'firefox.exe': 'Mozilla Firefox',
      'brave.exe': 'Brave Browser',
      'powershell.exe': 'Windows PowerShell',
      'pwsh.exe': 'PowerShell Core',
      'cmd.exe': 'Command Prompt',
      'windowsterminal.exe': 'Windows Terminal',
      'openconsole.exe': 'Windows Terminal Console',
      'explorer.exe': 'File Explorer',
      'systemsettings.exe': 'Windows Settings',
      'notepad.exe': 'Notepad',
      'taskmgr.exe': 'Task Manager',
      'calc.exe': 'Calculator',
      'calculatorapp.exe': 'Calculator',
      'mspaint.exe': 'Paint',
      'code.exe': 'Visual Studio Code',
      'winword.exe': 'Microsoft Word',
      'excel.exe': 'Microsoft Excel',
      'powerpnt.exe': 'Microsoft PowerPoint',
      'onedrive.exe': 'Microsoft OneDrive',
      'teams.exe': 'Microsoft Teams',
      'ms-teams.exe': 'Microsoft Teams',
      'slack.exe': 'Slack',
      'widgets.exe': 'Windows Widgets',
      'mmc.exe': 'Microsoft Management Console',
      'regedit.exe': 'Registry Editor',
      'mstsc.exe': 'Remote Desktop Connection',
      'python.exe': 'Python Interpreter',
      'node.exe': 'Node.js Runtime',
    };
    const bgSystemInUserSession = new Set([
      'csrss.exe', 'winlogon.exe', 'dwm.exe', 'fontdrvhost.exe', 'sihost.exe',
      'svchost.exe', 'taskhostw.exe', 'runtimebroker.exe', 'ctfmon.exe',
      'textinputhost.exe', 'startmenuexperiencehost.exe', 'searchhost.exe',
      'shellexperiencehost.exe', 'applicationframehost.exe', 'conhost.exe',
      'dllhost.exe', 'backgroundtaskhost.exe', 'securityhealthsystray.exe',
      'vm3dservice.exe', 'vmtoolsd.exe', 'tabtip.exe', 'crossdeviceresume.exe',
      'widgetservice.exe', 'msedgewebview2.exe', 'smartscreen.exe',
      'logonui.exe', 'lockapp.exe', 'shellhost.exe', 'monotificationux.exe', 'onedrivesetup.exe'
    ]);

    const enriched: Data[] = rawItems.map((p): Data => {
      const lowName = String(p.name || '').trim().toLowerCase();
      const sessId = Number(p.session_id || 0);
      const acct = String(p.account || '');
      const isApp = Boolean(
        p.is_running_app ??
        (appCatalog[lowName] ||
          (sessId > 0 &&
            !bgSystemInUserSession.has(lowName) &&
            acct &&
            !acct.toUpperCase().startsWith('NT AUTHORITY\\') &&
            !acct.toUpperCase().startsWith('WINDOW MANAGER\\') &&
            !acct.toUpperCase().startsWith('FONT DRIVER HOST\\')))
      );
      const cleanBase = String(p.name || 'Application').replace(/\.exe$/i, '');
      const appName = p.app_name || (isApp ? appCatalog[lowName] || cleanBase : null);
      const category = p.process_category || (isApp ? 'App' : sessId > 0 ? 'Background' : 'System');
      return {
        ...p,
        is_running_app: isApp,
        app_name: appName,
        process_category: category,
      };
    });

    enriched.sort((a, b) => {
      const aObs = a.observed_state === 'Observed' ? 1 : 0;
      const bObs = b.observed_state === 'Observed' ? 1 : 0;
      if (aObs !== bObs) return bObs - aObs;
      const aTier = a.is_running_app ? 2 : Number(a.session_id || 0) > 0 ? 1 : 0;
      const bTier = b.is_running_app ? 2 : Number(b.session_id || 0) > 0 ? 1 : 0;
      if (aTier !== bTier) return bTier - aTier;
      return Number(b.working_set_bytes || 0) - Number(a.working_set_bytes || 0);
    });

    if (Array.isArray(procData?.running_apps) && procData.running_apps.length > 0) {
      return { items: enriched, runningApps: procData.running_apps };
    }

    const groups: Record<string, Data> = {};
    for (const x of enriched) {
      if (!x.is_running_app || (x.observed_state && x.observed_state !== 'Observed')) continue;
      const gkey = `${x.device_id || ''}:${String(x.app_name || x.name || '').toLowerCase()}`;
      const ws = Number(x.working_set_bytes || 0);
      const cpu = typeof x.cpu_percent === 'number' ? x.cpu_percent : 0;
      if (!groups[gkey]) {
        groups[gkey] = {
          app_name: x.app_name || x.name,
          name: x.name,
          instance_key: x.instance_key || x.process_key,
          primary_pid: x.pid,
          process_count: 1,
          account: x.account || x.user_sid || 'Interactive user',
          working_set_bytes: ws,
          cpu_percent: typeof x.cpu_percent === 'number' ? cpu : null,
          _max_ws: ws,
          observed_state: 'Running',
        };
      } else {
        const g = groups[gkey];
        g.process_count += 1;
        g.working_set_bytes += ws;
        if (typeof x.cpu_percent === 'number') {
          g.cpu_percent = Number(g.cpu_percent || 0) + cpu;
        }
        if (ws > g._max_ws) {
          g._max_ws = ws;
          g.instance_key = x.instance_key || x.process_key;
          g.primary_pid = x.pid;
        }
      }
    }
    const computedApps = Object.values(groups).sort(
      (a, b) => Number(b.working_set_bytes || 0) - Number(a.working_set_bytes || 0)
    );
    return { items: enriched, runningApps: computedApps };
  }, [procData]);

  const lifecycleItems: Data[] = historyData?.items || [];
  const treeRoots: Data[] = treeData?.roots || [];

  const totalDeviceCpu = useMemo(() => {
    if (currentDeviceObj?.health?.cpu != null) {
      return Number(currentDeviceObj.health.cpu);
    }
    const sum = items.reduce((acc, p) => acc + (typeof p.cpu_percent === 'number' ? p.cpu_percent : 0), 0);
    const hasMeasured = items.some(p => typeof p.cpu_percent === 'number');
    return hasMeasured ? Math.min(100, sum) : null;
  }, [currentDeviceObj, items]);

  const memoryStats = useMemo(() => {
    if (currentDeviceObj?.health?.ram_used != null && currentDeviceObj?.health?.ram_total != null) {
      const used = Number(currentDeviceObj.health.ram_used);
      const total = Number(currentDeviceObj.health.ram_total);
      const pct = total > 0 ? Math.min(100, (used / total) * 100) : 0;
      return {
        label: `${formatGiBFromBytes(used)} / ${formatGiBFromBytes(total)} GiB`,
        percent: pct,
        sub: 'Device physical memory reported'
      };
    }
    const wsSum = items.reduce((acc, p) => acc + (typeof p.working_set_bytes === 'number' ? p.working_set_bytes : 0), 0);
    if (wsSum > 0) {
      return {
        label: `${formatMiB(wsSum)}`,
        percent: Math.min(100, (wsSum / (4 * 1024 * 1024 * 1024)) * 100),
        sub: 'Sum of observed process working sets'
      };
    }
    return { label: 'Unavailable', percent: 0, sub: 'Awaiting device memory sample' };
  }, [currentDeviceObj, items]);

  const trackedStartsCount = useMemo(() => {
    if (typeof procData?.summary?.lifecycle_events_count === 'number' && procData.summary.lifecycle_events_count > 0) {
      return procData.summary.lifecycle_events_count;
    }
    if (typeof procData?.summary?.total_matching_instances === 'number') {
      return procData.summary.total_matching_instances;
    }
    return items.length;
  }, [procData, items]);

  const snapshotFreshness = useMemo(() => {
    if (!latestSnapshot) {
      return { connected: false, label: 'No snapshot received', age: '—', complete: true };
    }
    const ageMs = Date.now() - new Date(latestSnapshot.observed_at || latestSnapshot.received_at).getTime();
    const isFresh = ageMs <= 120000;
    const isComplete = latestSnapshot.is_complete == null ? true : Boolean(latestSnapshot.is_complete);
    return {
      connected: isFresh,
      label: !isComplete ? 'Partial snapshot' : isFresh ? 'Agent connected' : 'Snapshot stale',
      age: formatAgeSeconds(latestSnapshot.observed_at || latestSnapshot.received_at),
      complete: isComplete
    };
  }, [latestSnapshot]);

  const selectedProcess =
    detailData?.instance ||
    (detailData?.instance_key ? detailData : null) ||
    items.find(p => (p.instance_key || p.process_key) === selectedKey) ||
    null;

  const ancestors: Data[] = detailData?.ancestors || [];
  const parentInstance = detailData?.parent || (ancestors.length > 0 ? ancestors[ancestors.length - 1] : null);
  const childInstances: Data[] = detailData?.children || [];
  const correlations: Data[] = detailData?.correlations || [];
  const procLifecycle: Data[] = detailData?.lifecycle_events || detailData?.lifecycle || [];

  return (
    <div className="pm-page">
      <div className="pm-header-row">
        <div>
          <h1>Process monitor</h1>
          <p>Read-only visibility into programs running on enrolled employee devices.</p>
        </div>
      </div>

      <ErrorBox message={error} />

      {/* Top Filter & Status Bar */}
      <div className="pm-controls-bar">
        <div className="pm-filter-group">
          <label className="pm-filter-item">
            <span>Device</span>
            <select
              aria-label="Select device"
              value={selectedDevice}
              onChange={e => {
                setSelectedDevice(e.target.value);
                setSearchParams(prev => {
                  const next = new URLSearchParams(prev);
                  if (e.target.value) next.set('device_id', e.target.value);
                  else next.delete('device_id');
                  return next;
                });
              }}
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
            <span>View</span>
            <select
              aria-label="Select view mode"
              value={activeTab}
              onChange={e => setActiveTab(e.target.value as 'live' | 'history' | 'tree')}
            >
              <option value="live">Live snapshot</option>
              <option value="history">Process history</option>
              <option value="tree">Process tree</option>
            </select>
          </label>

          <label className="pm-filter-item">
            <span>Refresh</span>
            <select
              aria-label="Select refresh interval"
              value={String(refreshSec)}
              onChange={e => setRefreshSec(Number(e.target.value))}
            >
              <option value="15">15 sec</option>
              <option value="30">30 sec</option>
              <option value="60">60 sec</option>
              <option value="0">Manual</option>
            </select>
          </label>
        </div>

        <div className="pm-status-pill-bar">
          <span className="pm-status-indicator">
            <span className={`dot ${snapshotFreshness.connected ? 'green' : latestSnapshot ? 'amber' : 'gray'}`} />
            <strong className={snapshotFreshness.connected ? 'text-green' : ''}>{snapshotFreshness.label}</strong>
          </span>
          <span className="pm-divider">|</span>
          <span>
            Snapshot age <strong>{snapshotFreshness.age}</strong>
          </span>
          <span className="pm-divider">|</span>
          <span>
            Processes observed{' '}
            <strong className="pm-count-highlight">
              {procData?.summary?.observed_processes ?? items.length}
            </strong>
          </span>
        </div>
      </div>

      {latestSnapshot && !snapshotFreshness.complete && (
        <div className="pm-warning-banner" role="status">
          <AlertTriangle size={16} />
          <span>
            Latest snapshot (<code>{latestSnapshot.id || latestSnapshot.snapshot_id}</code>) is incomplete. Missing processes are not marked exited until a complete snapshot is assembled.
          </span>
        </div>
      )}

      {/* 3 KPI Summary Cards */}
      <div className="pm-kpi-grid">
        <div className="pm-kpi-card">
          <div className="pm-kpi-icon teal">
            <Cpu size={22} />
          </div>
          <div className="pm-kpi-body">
            <span className="pm-kpi-label">Total device CPU</span>
            <strong className="pm-kpi-value">
              {totalDeviceCpu != null ? `${totalDeviceCpu.toFixed(0)}%` : 'Unavailable'}
            </strong>
            <div className="health-bar-track">
              <div
                className="health-bar-fill"
                style={{
                  width: `${totalDeviceCpu != null ? Math.min(100, Math.max(3, totalDeviceCpu)) : 0}%`,
                  background: '#10b981'
                }}
              />
            </div>
          </div>
        </div>

        <div className="pm-kpi-card">
          <div className="pm-kpi-icon blue">
            <HardDrive size={22} />
          </div>
          <div className="pm-kpi-body">
            <span className="pm-kpi-label">Memory used</span>
            <strong className="pm-kpi-value">{memoryStats.label}</strong>
            <div className="health-bar-track">
              <div
                className="health-bar-fill"
                style={{
                  width: `${Math.min(100, Math.max(4, memoryStats.percent))}%`,
                  background: '#2563eb'
                }}
              />
            </div>
          </div>
        </div>

        <div className="pm-kpi-card">
          <div className="pm-kpi-icon indigo">
            <ClipboardList size={22} />
          </div>
          <div className="pm-kpi-body">
            <span className="pm-kpi-label">Tracked starts today</span>
            <div style={{ display: 'flex', alignItems: 'flex-end', justifyContent: 'space-between', gap: '12px' }}>
              <strong className="pm-kpi-value">{trackedStartsCount}</strong>
              <div className="pm-mini-bars" aria-hidden="true">
                {[28, 42, 35, 55, 48, 65, 80, 95].map((h, i) => (
                  <span key={i} style={{ height: `${Math.max(18, Math.round((h / 100) * 32))}px` }} />
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Main Split Workspace */}
      <div className="pm-workspace-grid">
        <div className="panel pm-main-panel">
          <div className="pm-tabs-header">
            <button
              type="button"
              className={`pm-tab-item ${activeTab === 'live' ? 'active' : ''}`}
              onClick={() => setActiveTab('live')}
            >
              Live processes
            </button>
            <button
              type="button"
              className={`pm-tab-item ${activeTab === 'apps' ? 'active' : ''}`}
              onClick={() => setActiveTab('apps')}
            >
              Running apps ({runningApps.length})
            </button>
            <button
              type="button"
              className={`pm-tab-item ${activeTab === 'history' ? 'active' : ''}`}
              onClick={() => setActiveTab('history')}
            >
              Process history
            </button>
            <button
              type="button"
              className={`pm-tab-item ${activeTab === 'tree' ? 'active' : ''}`}
              onClick={() => setActiveTab('tree')}
            >
              Process tree
            </button>
          </div>

          <div className="pm-search-bar-wrap">
            <Search size={16} className="pm-search-icon" />
            <input
              type="search"
              placeholder="Search apps or processes by name, user, or PID..."
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
            />
          </div>

          {(activeTab === 'live' || activeTab === 'apps') && runningApps.length > 0 && (
            <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border, #e2e8f0)', background: 'rgba(248, 250, 252, 0.7)' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '10px' }}>
                <span style={{ fontSize: '12px', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.04em', color: '#334155' }}>
                  Running Applications on Device ({runningApps.length})
                </span>
                <span style={{ fontSize: '12px', color: '#64748b' }}>
                  Click any running app to inspect process evidence & lineage
                </span>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))', gap: '10px' }}>
                {runningApps.map((app: Data) => {
                  const isSel = app.instance_key === selectedKey;
                  return (
                    <div
                      key={app.instance_key || app.app_name}
                      onClick={() => app.instance_key && setSelectedKey(app.instance_key)}
                      style={{
                        cursor: 'pointer',
                        padding: '10px 12px',
                        borderRadius: '10px',
                        border: isSel ? '2px solid #2563eb' : '1px solid #cbd5e1',
                        background: isSel ? '#eff6ff' : '#ffffff',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        gap: '10px',
                        boxShadow: '0 1px 2px rgba(15, 23, 42, 0.04)'
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: '10px', minWidth: 0 }}>
                        <ProcessIcon name={app.name} size={18} />
                        <div style={{ minWidth: 0 }}>
                          <div style={{ fontWeight: 700, fontSize: '13px', color: '#0f172a', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                            {app.app_name}
                          </div>
                          <div style={{ fontSize: '11px', color: '#64748b', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                            {app.name} · {app.process_count > 1 ? `${app.process_count} procs` : `PID ${app.primary_pid}`}
                          </div>
                        </div>
                      </div>
                      <div style={{ textAlign: 'right', flexShrink: 0 }}>
                        <div style={{ fontSize: '11px', fontWeight: 600, color: '#059669', display: 'flex', alignItems: 'center', justifyContent: 'flex-end', gap: '4px' }}>
                          <span className="dot green" /> Running
                        </div>
                        <div style={{ fontSize: '11px', color: '#475569' }}>
                          {formatMiB(app.working_set_bytes)}
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {(activeTab === 'live' || activeTab === 'apps') && (
            items.length === 0 ? (
              <Empty title="No processes observed in latest snapshot">
                Start the endpoint agent on LAB-PC01 or switch to Process history to inspect earlier process instances.
              </Empty>
            ) : (
              <div className="table-wrap">
                <table className="pm-table">
                  <thead>
                    <tr>
                      <th>Application / Process</th>
                      <th>Type</th>
                      <th>PID</th>
                      <th>User</th>
                      <th>CPU</th>
                      <th>Working set</th>
                      <th>State</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(activeTab === 'apps' ? items.filter(p => p.is_running_app) : items).map(proc => {
                      const pKey = proc.instance_key || proc.process_key;
                      const isSelected = pKey === selectedKey;
                      const obsState = proc.observed_state || proc.state || 'Observed';
                      const stateLabel =
                        obsState === 'Observed' || obsState === 'active'
                          ? proc.is_running_app ? 'Running' : 'Observed'
                          : obsState === 'Exited' || obsState === 'exited'
                          ? 'Exited'
                          : 'No longer observed';
                      const stateDot =
                        stateLabel === 'Observed' || stateLabel === 'Running' ? 'green' : stateLabel === 'Exited' ? 'gray' : 'amber';
                      const cat = proc.process_category || (proc.is_running_app ? 'App' : 'System');
                      return (
                        <tr
                          key={pKey}
                          className={isSelected ? 'pm-row-selected' : ''}
                          onClick={() => setSelectedKey(pKey)}
                          style={{ cursor: 'pointer' }}
                        >
                          <td>
                            <div className="pm-proc-cell">
                              <ProcessIcon name={proc.name} />
                              <div>
                                <strong>{proc.app_name ? `${proc.app_name} (${proc.name})` : proc.name}</strong>
                              </div>
                            </div>
                          </td>
                          <td>
                            <Badge tone={cat === 'App' ? 'Good' : cat === 'Background' ? 'Info' : 'Neutral'}>
                              {cat}
                            </Badge>
                          </td>
                          <td>{proc.pid}</td>
                          <td>{proc.account || proc.user_sid || 'Unknown'}</td>
                          <td>
                            {typeof proc.cpu_percent === 'number'
                              ? `${proc.cpu_percent.toFixed(1)}%`
                              : 'Unavailable'}
                          </td>
                          <td>{formatMiB(proc.working_set_bytes)}</td>
                          <td>
                            <span className="pm-state-cell">
                              <span className={`dot ${stateDot}`} />
                              {stateLabel}
                            </span>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )
          )}

          {activeTab === 'history' && (
            lifecycleItems.length === 0 && items.length === 0 ? (
              <Empty title="No process lifecycle records in this period">
                Enable Windows Audit Process Creation (4688/4689) or optional Sysmon Event IDs 1/5 on LAB-PC01.
              </Empty>
            ) : (
              <div className="table-wrap">
                <table className="pm-table">
                  <thead>
                    <tr>
                      <th>Time</th>
                      <th>Process</th>
                      <th>PID</th>
                      <th>User</th>
                      <th>Event</th>
                      <th>Source</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(lifecycleItems.length > 0 ? lifecycleItems : items).map((ev: Data, idx: number) => {
                      const key = ev.instance_key || ev.process_key || '';
                      const isStart = ev.event_type === 'start' || ev.event_id === 4688 || ev.event_id === 1;
                      const isExit =
                        ev.event_type === 'exit' ||
                        ev.event_id === 4689 ||
                        ev.event_id === 5 ||
                        ev.observed_state === 'Exited';
                      return (
                        <tr
                          key={ev.id || key || idx}
                          className={key && key === selectedKey ? 'pm-row-selected' : ''}
                          onClick={() => key && setSelectedKey(key)}
                          style={{ cursor: key ? 'pointer' : 'default' }}
                        >
                          <td>
                            <Time value={ev.event_time || ev.creation_time || ev.first_seen_at} />
                          </td>
                          <td>
                            <div className="pm-proc-cell">
                              <ProcessIcon name={ev.name} />
                              <strong>{ev.name || 'Unknown'}</strong>
                            </div>
                          </td>
                          <td>{ev.pid ?? '—'}</td>
                          <td>{ev.account || ev.user_sid || 'Unknown'}</td>
                          <td>
                            <Badge tone={isStart ? 'online' : isExit ? 'closed' : 'observed'}>
                              {isStart ? 'Started' : isExit ? 'Exited' : ev.observed_state || 'Observed'}
                            </Badge>
                          </td>
                          <td>
                            <small>{ev.source_channel || ev.source_kind || 'Endpoint snapshot'}</small>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )
          )}

          {activeTab === 'tree' && (
            treeRoots.length === 0 ? (
              <Empty title="No process lineage nodes available">
                Lineage trees are constructed from verified parent creation times or Sysmon ProcessGuid links.
              </Empty>
            ) : (
              <div className="pm-tree-container">
                {treeRoots.map((root: Data) => (
                  <ProcessTreeNode
                    key={root.instance_key || root.process_key}
                    node={root}
                    depth={0}
                    selectedKey={selectedKey}
                    onSelect={setSelectedKey}
                  />
                ))}
              </div>
            )
          )}
        </div>

        {/* Right Column: Process Details & Lineage Drawer */}
        <aside className="panel pm-detail-panel">
          {!selectedProcess ? (
            <Empty title="Select a process to inspect">
              Click any row in the process list to view its executable path, signature status, command line, and parent-child lineage.
            </Empty>
          ) : (
            <div className="pm-detail-content">
              <div className="pm-detail-header">
                <ProcessIcon name={selectedProcess.name} size={24} />
                <div>
                  <h2>{selectedProcess.name}</h2>
                  <p>User: {selectedProcess.account || selectedProcess.user_sid || 'Unknown'}</p>
                </div>
              </div>

              <div className="pm-kv-table">
                <div className="pm-kv-row">
                  <span>Path</span>
                  <strong title={selectedProcess.executable_path || selectedProcess.exe_path || ''}>
                    {selectedProcess.executable_path || selectedProcess.exe_path || 'Unavailable'}
                  </strong>
                </div>
                <div className="pm-kv-row">
                  <span>PID</span>
                  <strong>
                    {selectedProcess.pid}{' '}
                    {selectedProcess.session_id != null && (
                      <small style={{ color: 'var(--muted)', fontWeight: 400 }}>
                        (Session {selectedProcess.session_id})
                      </small>
                    )}
                  </strong>
                </div>
                <div className="pm-kv-row">
                  <span>Start time</span>
                  <strong>
                    <Time value={selectedProcess.creation_time || selectedProcess.first_seen_at} />
                  </strong>
                </div>
                <div className="pm-kv-row">
                  <span>Parent process</span>
                  <strong style={{ display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap' }}>
                    <span>
                      {parentInstance
                        ? `${parentInstance.name} (PID ${parentInstance.pid})`
                        : selectedProcess.parent_name
                        ? `${selectedProcess.parent_name} (PID ${selectedProcess.parent_pid ?? '?'})`
                        : selectedProcess.parent_pid
                        ? `PID ${selectedProcess.parent_pid}`
                        : 'Unavailable'}
                    </span>
                    {selectedProcess.parent_instance_key ? (
                      <Badge tone="online">Verified</Badge>
                    ) : selectedProcess.parent_pid ? (
                      <Badge tone="stale">Unverified PID</Badge>
                    ) : null}
                  </strong>
                </div>
                <div className="pm-kv-row">
                  <span>Signature</span>
                  <strong>
                    {selectedProcess.signature_state || selectedProcess.signature_status || 'Not collected'}
                    {selectedProcess.signer ? ` (${selectedProcess.signer})` : ''}
                  </strong>
                </div>
                {selectedProcess.sha256 && (
                  <div className="pm-kv-row">
                    <span>SHA-256</span>
                    <code style={{ fontSize: '10.5px', wordBreak: 'break-all' }}>{selectedProcess.sha256}</code>
                  </div>
                )}
                <div className="pm-kv-row">
                  <span>Command line</span>
                  <strong>
                    {selectedProcess.command_line ? (
                      <code className="pm-cmd-pill">{selectedProcess.command_line}</code>
                    ) : (
                      <span className="muted">
                        {selectedProcess.command_line_state || 'Not collected'}
                      </span>
                    )}
                  </strong>
                </div>
                <div className="pm-kv-row">
                  <span>Source</span>
                  <strong>{selectedProcess.source_kind || 'Endpoint snapshot'}</strong>
                </div>
              </div>

              <div className="pm-info-callout">
                <Info size={16} />
                <span>
                  {/powershell|pwsh|cmd/i.test(selectedProcess.name || '')
                    ? 'PowerShell use alone is not malicious.'
                    : 'Observation in a snapshot records resource use and lineage; it is not an automated maliciousness verdict.'}
                </span>
              </div>

              {/* Process Lineage Visual Chain */}
              <div className="pm-section-block">
                <h3>Process lineage</h3>
                <div className="pm-lineage-flow">
                  {parentInstance || selectedProcess.parent_pid ? (
                    <>
                      <div
                        className="pm-lineage-box"
                        onClick={() => {
                          const pk = parentInstance?.instance_key || parentInstance?.process_key;
                          if (pk) setSelectedKey(pk);
                        }}
                        style={{
                          cursor:
                            parentInstance?.instance_key || parentInstance?.process_key
                              ? 'pointer'
                              : 'default'
                        }}
                      >
                        <ProcessIcon
                          name={parentInstance?.name || selectedProcess.parent_name || 'explorer.exe'}
                          size={16}
                        />
                        <div>
                          <strong>
                            {parentInstance?.name || selectedProcess.parent_name || 'Parent process'}
                          </strong>
                          <small>PID {parentInstance?.pid ?? selectedProcess.parent_pid}</small>
                        </div>
                      </div>
                      <ArrowRight size={16} className="pm-lineage-arrow" />
                    </>
                  ) : null}

                  <div className="pm-lineage-box active">
                    <ProcessIcon name={selectedProcess.name} size={16} />
                    <div>
                      <strong>{selectedProcess.name}</strong>
                      <small>PID {selectedProcess.pid}</small>
                    </div>
                  </div>

                  {childInstances.length > 0 && (
                    <>
                      <ArrowRight size={16} className="pm-lineage-arrow" />
                      <div
                        className="pm-lineage-box"
                        onClick={() =>
                          setSelectedKey(
                            childInstances[0].instance_key || childInstances[0].process_key
                          )
                        }
                        style={{ cursor: 'pointer' }}
                      >
                        <ProcessIcon name={childInstances[0].name} size={16} />
                        <div>
                          <strong>{childInstances[0].name}</strong>
                          <small>
                            PID {childInstances[0].pid}
                            {childInstances.length > 1 ? ` (+${childInstances.length - 1})` : ''}
                          </small>
                        </div>
                      </div>
                    </>
                  )}
                </div>
              </div>

              {/* Correlated Browser Download Link */}
              {correlations.length > 0 && (
                <div className="pm-section-block">
                  <h3>Correlated browser activity</h3>
                  <div className="pm-corr-card">
                    <div>
                      <strong>{correlations[0].relationship_label || 'Linked to browser download'}</strong>
                      <small>
                        Confidence: {correlations[0].confidence} · Case: {correlations[0].case_key}
                      </small>
                    </div>
                    <Link
                      to={`/timeline?case_key=${encodeURIComponent(correlations[0].case_key)}`}
                      className="button primary"
                      style={{ padding: '6px 10px', fontSize: '11.5px' }}
                    >
                      Open timeline <ChevronRight size={14} />
                    </Link>
                  </div>
                </div>
              )}

              {/* Recent Process Events Mini Table */}
              <div className="pm-section-block">
                <div
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    marginBottom: '8px'
                  }}
                >
                  <h3 style={{ margin: 0 }}>Recent process events</h3>
                  <button
                    type="button"
                    className="pm-link-btn"
                    onClick={() => setActiveTab('history')}
                  >
                    View all
                  </button>
                </div>
                <div className="table-wrap">
                  <table className="pm-mini-table">
                    <thead>
                      <tr>
                        <th>Time</th>
                        <th>Process</th>
                        <th>Event</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(procLifecycle.length > 0 ? procLifecycle : lifecycleItems.slice(0, 4)).map(
                        (ev: Data, idx: number) => (
                          <tr key={ev.id || idx}>
                            <td>
                              {ev.event_time
                                ? new Date(ev.event_time).toLocaleTimeString('en-GB')
                                : '—'}
                            </td>
                            <td>{ev.name || selectedProcess.name}</td>
                            <td>
                              {ev.event_type === 'exit' || ev.event_id === 4689 || ev.event_id === 5
                                ? 'Exited'
                                : 'Started'}
                            </td>
                          </tr>
                        )
                      )}
                      {procLifecycle.length === 0 && lifecycleItems.length === 0 && (
                        <tr>
                          <td>
                            {selectedProcess.first_seen_at
                              ? new Date(selectedProcess.first_seen_at).toLocaleTimeString('en-GB')
                              : '—'}
                          </td>
                          <td>{selectedProcess.name}</td>
                          <td>Observed</td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>

              <details>
                <summary>Technical evidence &amp; raw sample history</summary>
                <Json value={detailData || selectedProcess} />
              </details>
            </div>
          )}
        </aside>
      </div>

      <div className="pm-footnote">
        CPU normalized to total logical CPU capacity • No process termination controls.
      </div>
    </div>
  );
}

function ProcessTreeNode({
  node,
  depth,
  selectedKey,
  onSelect
}: {
  node: Data;
  depth: number;
  selectedKey: string;
  onSelect: (k: string) => void;
}) {
  const nKey = node.instance_key || node.process_key;
  const isSelected = nKey === selectedKey;
  const children: Data[] = node.children || [];
  return (
    <div style={{ marginLeft: depth > 0 ? '22px' : '0' }}>
      <div
        className={`pm-tree-row ${isSelected ? 'selected' : ''}`}
        onClick={() => onSelect(nKey)}
      >
        <GitBranch size={14} style={{ color: 'var(--muted)' }} />
        <ProcessIcon name={node.name} size={15} />
        <strong>{node.name}</strong>
        <span className="muted">PID {node.pid}</span>
        <span className="muted">· {node.account || node.user_sid || 'Unknown'}</span>
        {node.parent_instance_key ? (
          <Badge tone="online">Verified lineage</Badge>
        ) : depth > 0 ? (
          <Badge tone="stale">Unverified PID</Badge>
        ) : null}
      </div>
      {children.map(child => (
        <ProcessTreeNode
          key={child.instance_key || child.process_key}
          node={child}
          depth={depth + 1}
          selectedKey={selectedKey}
          onSelect={onSelect}
        />
      ))}
    </div>
  );
}
