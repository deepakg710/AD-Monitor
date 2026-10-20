import { useState, useEffect, useCallback, useRef } from 'react';
import { Routes, Route, NavLink, Link, useLocation } from 'react-router-dom';
import {
  Shield, LayoutDashboard, Bell, Users, Monitor, Search, Usb, SlidersHorizontal,
  FileText, Activity, Settings, Sun, Moon, LogOut, RefreshCw, Clock, Fingerprint,
  ArrowUpRight, Volume2, VolumeX, BookOpen, Cpu, Globe
} from 'lucide-react';
import { Context, api, setCsrf, Badge, Empty, ErrorBox } from './core';
import type { User, Data } from './core';
import { Overview, Events, EventDetail } from './Evidence';
import { Alerts, Investigation } from './Cases';
import { Inventory, DeviceDetail, EmployeeDetail, USB } from './Inventory';
import { Rules, Reports, Diagnostics, SettingsPage } from './Administration';
import { AttackLibrary, AttackDetail, TeacherPresentation } from './AttackLibrary';
import { ProcessMonitor } from './ProcessMonitor';
import { BrowserActivity } from './BrowserActivity';
import { InvestigationTimeline } from './InvestigationTimeline';

const NAV = [
  ['/', 'Overview', LayoutDashboard],
  ['/processes', 'Process Monitor', Cpu],
  ['/browser-activity', 'Browser Activity', Globe],
  ['/timeline', 'Investigation Timeline', Clock],
  ['/alerts', 'Alerts', Bell],
  ['/employees', 'Employees', Users],
  ['/devices', 'Devices', Monitor],
  ['/attack-library', 'Attack Library', BookOpen],
  ['/events', 'Event Explorer', Search],
  ['/usb', 'USB History', Usb],
  ['/rules', 'Rules & Behavior', SlidersHorizontal],
  ['/reports', 'Reports', FileText],
  ['/diagnostics', 'Diagnostics', Activity],
  ['/settings', 'Settings', Settings]
] as const;

function playRadarChime() {
  try {
    const AudioCtx = window.AudioContext || (window as any).webkitAudioContext;
    if (!AudioCtx) return;
    const ctx = new AudioCtx();
    if (ctx.state === 'suspended') ctx.resume();
    const notes = [
      { freq: 980, start: 0.0, dur: 0.16 },
      { freq: 740, start: 0.18, dur: 0.16 },
      { freq: 1175, start: 0.36, dur: 0.28 }
    ];
    notes.forEach(({ freq, start, dur }) => {
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = 'triangle';
      osc.frequency.setValueAtTime(freq, ctx.currentTime + start);
      gain.gain.setValueAtTime(0.28, ctx.currentTime + start);
      gain.gain.exponentialRampToValueAtTime(0.005, ctx.currentTime + start + dur);
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.start(ctx.currentTime + start);
      osc.stop(ctx.currentTime + start + dur);
    });
  } catch {}
}

function Login({ onLogin }: { onLogin: (u: User) => void }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [initialized, setInitialized] = useState(true);

  useEffect(() => {
    api('/auth/status').then(d => setInitialized(d.initialized)).catch(e => setError(e.message));
  }, []);

  return (
    <div className="login-page">
      <div className="login-story">
        <div className="brand">
          <Shield size={38} />
          <div>AD MONITOR<small>LAB SECURITY WORKSPACE</small></div>
        </div>
        <div>
          <span className="eyebrow">VISIBILITY. CONTEXT. EVIDENCE.</span>
          <h1>Understand activity.<br />Investigate with clarity.</h1>
          <p>Windows evidence, endpoint health, and behavior analysis in one focused workspace.</p>
          <div className="login-feature"><Fingerprint />Trace each finding to its source.</div>
          <div className="login-feature"><Monitor />Know which devices are reporting.</div>
          <div className="login-feature"><Shield />Keep decisions grounded in human review.</div>
        </div>
        <span className="login-foot">PRIVATE LAB APPLICATION · NO CLOUD API REQUIRED</span>
      </div>
      <div className="login-form-wrap">
        <form
          className="login-form"
          onSubmit={async e => {
            e.preventDefault();
            setBusy(true);
            setError('');
            try {
              if (!initialized) {
                if (password.length < 12) {
                  throw new Error('Administrator passphrase must be at least 12 characters.');
                }
                if (password !== confirmPassword) {
                  throw new Error('Passphrase confirmation does not match.');
                }
                await api('/auth/setup', { method: 'POST', body: JSON.stringify({ username, password }) });
                setInitialized(true);
              }
              const d = await api('/auth/login', { method: 'POST', body: JSON.stringify({ username, password }) });
              setCsrf(d.csrf, d.token);
              onLogin({ ...d.user, csrf: d.csrf });
            } catch (e: any) {
              setError(e.message);
            } finally {
              setBusy(false);
            }
          }}
        >
          <Badge tone="success">LOCAL WORKSPACE</Badge>
          <h2>{initialized ? 'Welcome to AD Monitor' : 'Initial Administrator Setup'}</h2>
          <p>{initialized ? 'Sign in with your application account.' : 'Create a unique administrator account (12+ character passphrase required).'}</p>
          <ErrorBox message={error} />
          {!initialized && (
            <div className="setup-notice">
              <strong>No default credentials exist</strong>
              <p>Create your unique administrator account below or run locally:</p>
              <code>python -m backend.cli create-admin --username &lt;your-admin&gt;</code>
            </div>
          )}
          <label>Username<input autoComplete="username" required value={username} onChange={e => setUsername(e.target.value)} /></label>
          <label>Password (12+ chars)<input type="password" autoComplete={initialized ? 'current-password' : 'new-password'} required minLength={initialized ? 1 : 12} value={password} onChange={e => setPassword(e.target.value)} /></label>
          {!initialized && (
            <label>Confirm Password<input type="password" autoComplete="new-password" required minLength={12} value={confirmPassword} onChange={e => setConfirmPassword(e.target.value)} /></label>
          )}
          <button className="primary" disabled={busy}>{busy ? (initialized ? 'Signing in…' : 'Creating admin…') : (initialized ? 'Sign in' : 'Create Admin & Sign In')}<ArrowUpRight size={17} /></button>
          <small>AD directory accounts and application accounts are separate.</small>
        </form>
      </div>
    </div>
  );
}

export default function App() {
  const [user, setUser] = useState<User | null>(null);
  const [checking, setChecking] = useState(true);
  const [theme, setTheme] = useState(localStorage.getItem('admonitor-theme') || 'dark');
  const [hours, setHours] = useState('24');
  const [start, setStart] = useState('');
  const [end, setEnd] = useState('');
  const [timezone, setTimezone] = useState('Asia/Kolkata');
  const [refresh, setRefresh] = useState(0);
  const [connection, setConnection] = useState('Connecting');
  const [lastSuccess, setLastSuccess] = useState<string | null>(null);
  const location = useLocation();
  const bump = useCallback(() => setRefresh(x => x + 1), []);
  const [clock, setClock] = useState(Date.now());
  const [soundEnabled, setSoundEnabled] = useState(localStorage.getItem('admonitor-sound') !== 'false');
  const lastAlertIdRef = useRef<string | null>(null);
  const [livePopup, setLivePopup] = useState<Data | null>(null);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem('admonitor-theme', theme);
  }, [theme]);

  useEffect(() => {
    localStorage.setItem('admonitor-sound', String(soundEnabled));
  }, [soundEnabled]);

  useEffect(() => {
    api('/auth/me').then(u => { setCsrf(u.csrf); setUser(u); }).catch(() => { }).finally(() => setChecking(false));
    const expired = () => { setUser(null); setCsrf('', ''); };
    window.addEventListener('session-expired', expired);
    return () => window.removeEventListener('session-expired', expired);
  }, []);

  useEffect(() => {
    if (!user) return;
    let live = true;
    const run = () => {
      api('/health').then(() => {
        if (live) {
          setConnection('Connected');
          setLastSuccess(new Date().toISOString());
        }
      }).catch(() => {
        if (live) setConnection('Disconnected · last received data');
      });

      // Poll open alerts every 3s for instant live popup + sound + auto-refresh
      api('/alerts?status=Open&page_size=5').then(res => {
        if (live && res.items && res.items.length > 0) {
          const latest = res.items[0];
          const sig = `${latest.id}_${latest.last_time}_${latest.title}`;
          if (lastAlertIdRef.current === null) {
            lastAlertIdRef.current = sig;
          } else if (sig !== lastAlertIdRef.current) {
            lastAlertIdRef.current = sig;
            setLivePopup(latest);
            setClock(Date.now());
            if (soundEnabled) playRadarChime();
          }
        } else if (live && res.items && res.items.length === 0) {
          lastAlertIdRef.current = 'EMPTY';
        }
      }).catch(() => { });
    };

    run();
    const t = setInterval(run, 3000);
    api('/settings').then(s => { if (live) setTimezone(s.timezone); }).catch(() => { });
    return () => { live = false; clearInterval(t); };
  }, [user, soundEnabled]);

  useEffect(() => {
    const t = setInterval(() => setClock(Date.now()), 4000);
    return () => clearInterval(t);
  }, []);

  const period = hours === 'custom' && start && end
    ? new URLSearchParams({ start: new Date(start + 'Z').toISOString(), end: new Date(end + 'Z').toISOString() }).toString()
    : new URLSearchParams({ start: new Date(clock - Number(hours === 'custom' ? 24 : hours) * 3600000).toISOString(), end: new Date(clock).toISOString() }).toString();

  if (checking) return <div className="boot"><Shield /><p>Opening AD Monitor…</p></div>;
  if (!user) return <Login onLogin={setUser} />;

  return (
    <Context.Provider value={{ user, timezone, period, refresh, bump }}>
      <div className="app-shell">
        <aside className="sidebar">
          <div className="sidebar-top">
            <Link className="brand" to="/">
              <Shield size={32} />
              <div>AD MONITOR<small>SECURITY WORKSPACE</small></div>
            </Link>
            <div className="workspace-chip">
              <span className="dot" />lab.local <span>PRIVATE LAB</span>
            </div>
            <div className="nav-label">WORKSPACE</div>
          </div>
          <nav>
            {NAV.map(([path, label, Icon]) => (
              <NavLink key={path} to={path} end={path === '/'}>
                <Icon size={19} />{label}
              </NavLink>
            ))}
          </nav>
          <div className="sidebar-bottom">
            <div className="profile">
              <div className="profile-avatar">{user.username.slice(0, 2).toUpperCase()}</div>
              <div>
                <strong>{user.username}</strong>
                <small>{user.role}</small>
              </div>
              <button
                title="Sign out"
                aria-label="Sign out"
                onClick={async () => {
                  try {
                    await api('/auth/logout', { method: 'POST' });
                    setUser(null);
                    setCsrf('', '');
                  } catch {
                    setConnection('Sign-out failed; reconnect and retry');
                  }
                }}
              >
                <LogOut size={17} />
              </button>
            </div>
            <small>AD Monitor 1.0 · College project</small>
          </div>
        </aside>

        <div className="main-shell">
          {livePopup && (
            <div
              role="alert"
              style={{
                position: 'fixed',
                top: '18px',
                right: '22px',
                zIndex: 9999,
                width: '410px',
                maxWidth: 'calc(100vw - 36px)',
                background: 'linear-gradient(135deg, #1e1b2e 0%, #0f172a 100%)',
                border: `2px solid ${livePopup.severity === 'High' ? '#ef4444' : '#f59e0b'}`,
                borderRadius: '12px',
                padding: '16px 18px',
                boxShadow: '0 20px 45px rgba(0,0,0,0.65), 0 0 24px rgba(239,68,68,0.35)',
                color: '#f8fafc'
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: '7px', fontSize: '11.5px', fontWeight: 700, letterSpacing: '0.06em', color: livePopup.severity === 'High' ? '#f87171' : '#fbbf24', textTransform: 'uppercase' }}>
                  <Bell size={15} /> LIVE SECURITY ALERT · {livePopup.severity}
                </span>
                <button
                  type="button"
                  onClick={() => setLivePopup(null)}
                  style={{ background: 'transparent', border: 'none', color: '#94a3b8', cursor: 'pointer', fontSize: '15px', padding: '2px 6px' }}
                  aria-label="Close alert popup"
                >
                  ✕
                </button>
              </div>
              <div style={{ fontSize: '15px', fontWeight: 700, color: '#ffffff', marginBottom: '6px', lineHeight: 1.35 }}>
                {livePopup.title}
              </div>
              <div style={{ fontSize: '12.5px', color: '#cbd5e1', marginBottom: '12px', lineHeight: 1.45 }}>
                <strong>Account:</strong> {livePopup.account || livePopup.user_sid || 'Unknown identity'}<br />
                {livePopup.explanation?.detail && (
                  <span>{String(livePopup.explanation.detail).slice(0, 150)}</span>
                )}
              </div>
              <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                <Link
                  to={'/alerts/' + livePopup.id}
                  onClick={() => setLivePopup(null)}
                  className="button primary"
                  style={{ padding: '6px 12px', fontSize: '12px' }}
                >
                  Investigate Alert ➔
                </Link>
                <button
                  type="button"
                  className="button"
                  style={{ padding: '6px 10px', fontSize: '12px', color: '#e2e8f0', borderColor: '#475569', background: 'rgba(255,255,255,0.06)' }}
                  onClick={() => playRadarChime()}
                >
                  <Volume2 size={13} /> Sound
                </button>
                <button
                  type="button"
                  className="button"
                  style={{ padding: '6px 10px', fontSize: '12px', color: '#94a3b8', borderColor: '#334155', background: 'transparent', marginLeft: 'auto' }}
                  onClick={() => setLivePopup(null)}
                >
                  Dismiss
                </button>
              </div>
            </div>
          )}
          {!location.pathname.startsWith('/present') && (
            <header className="topbar">
              <div>
                <span className={'dot ' + (connection === 'Connected' ? 'green' : 'amber')} />
                <span>{connection}</span>
                <small>Live auto-refresh (3s){lastSuccess && ' · ' + new Date(lastSuccess).toLocaleTimeString()}</small>
              </div>
              <div className="actions">
                <button
                  type="button"
                  className="button"
                  style={{ padding: '5px 10px', fontSize: '11.5px', borderColor: '#ef4444', color: '#ef4444' }}
                  title="Reset all alerts, events, and USB logs to 0"
                  onClick={async () => {
                    try {
                      await api('/admin/reset-telemetry', { method: 'POST' });
                      lastAlertIdRef.current = 'EMPTY';
                      setLivePopup(null);
                      setClock(Date.now());
                      bump();
                    } catch (e: any) {
                      setConnection(e.message || 'Reset failed');
                    }
                  }}
                >
                  <RefreshCw size={13} /> Reset All to 0
                </button>
                <Link to="/present" className="button" style={{ padding: '5px 10px', fontSize: '11.5px' }}>
                  <Monitor size={14} /> Teacher Presentation
                </Link>
                <span className="timezone"><Clock size={14} />{timezone}</span>
                <button
                  className="icon-button"
                  aria-label="Toggle SOC alarm chime"
                  title={soundEnabled ? 'SOC radar sound ON' : 'SOC radar sound MUTED'}
                  onClick={() => {
                    const next = !soundEnabled;
                    setSoundEnabled(next);
                    if (next) playRadarChime();
                  }}
                >
                  {soundEnabled ? <Volume2 size={17} style={{ color: '#00f2fe' }} /> : <VolumeX size={17} />}
                </button>
                <button className="icon-button" aria-label="Refresh data" onClick={bump}><RefreshCw size={17} /></button>
                <button className="icon-button" aria-label="Toggle theme" onClick={() => setTheme(theme === 'light' ? 'dark' : 'light')}>
                  {theme === 'light' ? <Moon size={18} /> : <Sun size={18} />}
                </button>
              </div>
            </header>
          )}

          <main key={location.pathname}>
            {!location.pathname.startsWith('/present') && !location.pathname.startsWith('/attack-library/') && (
              <div className="period-control">
                <Clock size={15} />
                <select aria-label="Selected period" value={hours} onChange={e => setHours(e.target.value)}>
                  <option value="24">Last 24 hours</option>
                  <option value="168">Last 7 days</option>
                  <option value="720">Last 30 days</option>
                  <option value="custom">Custom period (UTC)</option>
                </select>
                {hours === 'custom' && (
                  <>
                    <label>From UTC<input type="datetime-local" value={start} onChange={e => setStart(e.target.value)} /></label>
                    <label>To UTC<input type="datetime-local" value={end} onChange={e => setEnd(e.target.value)} /></label>
                  </>
                )}
              </div>
            )}

            <Routes>
              <Route path="/" element={<Overview />} />
              <Route path="/processes" element={<ProcessMonitor />} />
              <Route path="/browser-activity" element={<BrowserActivity />} />
              <Route path="/timeline" element={<InvestigationTimeline />} />
              <Route path="/attack-library" element={<AttackLibrary />} />
              <Route path="/attack-library/:id" element={<AttackDetail />} />
              <Route path="/present" element={<TeacherPresentation />} />
              <Route path="/present/:typeId" element={<TeacherPresentation />} />
              <Route path="/present/case/:alertId" element={<TeacherPresentation />} />
              <Route path="/events" element={<Events />} />
              <Route path="/events/:id" element={<EventDetail />} />
              <Route path="/alerts" element={<Alerts />} />
              <Route path="/alerts/:id" element={<Investigation />} />
              <Route path="/employees" element={<Inventory kind="employees" />} />
              <Route path="/employees/:sid" element={<EmployeeDetail />} />
              <Route path="/devices" element={<Inventory kind="devices" />} />
              <Route path="/devices/:id" element={<DeviceDetail />} />
              <Route path="/usb" element={<USB />} />
              <Route path="/rules" element={<Rules />} />
              <Route path="/reports" element={<Reports />} />
              <Route path="/diagnostics" element={<Diagnostics />} />
              <Route path="/settings" element={<SettingsPage />} />
              <Route path="*" element={<Empty title="Page not found"><Link to="/">Return to overview</Link></Empty>} />
            </Routes>

            <footer>
              <Shield size={13} />
              Evidence first. Human review always.
              <span>Display: {timezone} · Stored timestamps: UTC</span>
            </footer>
          </main>
        </div>
      </div>
    </Context.Provider>
  );
}
