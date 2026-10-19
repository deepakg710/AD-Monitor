import { useState, useEffect, createContext, useContext } from 'react';
import type { ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { Database, AlertTriangle, ChevronRight } from 'lucide-react';
import { ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip, CartesianGrid } from 'recharts';

export type Data = Record<string, any>;
export type User = { id: string; username: string; role: string; csrf: string };

export let csrf = localStorage.getItem('admonitor_csrf') || '';
export let authToken = localStorage.getItem('admonitor_token') || '';

export const setCsrf = (s: string, t?: string) => {
  csrf = s;
  localStorage.setItem('admonitor_csrf', s);
  if (t !== undefined) {
    authToken = t;
    if (t) localStorage.setItem('admonitor_token', t);
    else localStorage.removeItem('admonitor_token');
  }
};

export async function api(path: string, options: RequestInit = {}) {
  const hdrs: Record<string, string> = {
    'Content-Type': 'application/json',
    'X-CSRF-Token': csrf,
    ...(options.headers as Record<string, string> || {})
  };
  if (authToken) hdrs['Authorization'] = 'Bearer ' + authToken;
  const r = await fetch('/api' + path, { credentials: 'include', ...options, headers: hdrs });
  let d: any;
  try {
    d = await r.json();
  } catch {
    throw Error('Unreadable server response');
  }
  if (!r.ok) {
    if (r.status === 401 && path != '/auth/login') window.dispatchEvent(new Event('session-expired'));
    throw Error(typeof d.detail === 'string' ? d.detail : JSON.stringify(d.detail));
  }
  return d;
}

export const Context = createContext<{ user: User; timezone: string; period: string; refresh: number; bump: () => void }>({} as any);

export function useData(path: string | null) {
  const { refresh } = useContext(Context);
  const [data, setData] = useState<any>(null);
  const [error, setError] = useState('');
  useEffect(() => {
    if (!path) return;
    let live = true;
    const run = () => api(path).then(d => {
      if (live) {
        setData(d);
        setError('');
      }
    }).catch(e => {
      if (live) setError(e.message);
    });
    run();
    const t = setInterval(run, 15000);
    return () => { live = false; clearInterval(t); };
  }, [path, refresh]);
  return { data, error };
}

export function Time({ value }: { value?: string | null }) {
  const { timezone } = useContext(Context);
  return value ? (
    <time title={value}>
      {new Date(value).toLocaleString('en-IN', { timeZone: timezone, dateStyle: 'medium', timeStyle: 'medium' })}
    </time>
  ) : <span className="muted">Not received</span>;
}

export function Badge({ children, tone = 'neutral' }: { children: ReactNode; tone?: string }) {
  return <span className={'badge ' + String(tone || 'neutral').toLowerCase().replaceAll(' ', '-')}>{children}</span>;
}

export function Empty({ title = 'No records in this period', children }: { title?: string; children?: ReactNode }) {
  return (
    <div className="empty">
      <Database size={27} />
      <strong>{title}</strong>
      <p>{children || 'Collected evidence will appear here when an authorized source sends data.'}</p>
    </div>
  );
}

export function ErrorBox({ message }: { message: string }) {
  return message ? <div role="alert" className="error"><AlertTriangle size={17} />{message}</div> : null;
}

export function Panel({ title, subtitle, action, children }: { title: string; subtitle?: string; action?: ReactNode; children: ReactNode }) {
  return (
    <section className="panel">
      <div className="panel-head">
        <div>
          <h2>{title}</h2>
          {subtitle && <p>{subtitle}</p>}
        </div>
        {action}
      </div>
      {children}
    </section>
  );
}

export function Json({ value }: { value: any }) {
  return <pre className="json">{typeof value === 'string' ? value : JSON.stringify(value, null, 2)}</pre>;
}

export function Page({ title, description, action, children }: { title: string; description: string; action?: ReactNode; children: ReactNode }) {
  return (
    <>
      <div className="page-heading">
        <div>
          <div className="eyebrow">LAB.LOCAL / SECURITY OPERATIONS</div>
          <h1>{title}</h1>
          <p>{description}</p>
        </div>
        {action}
      </div>
      {children}
    </>
  );
}

export function Pager({ data, page, setPage }: { data: Data; page: number; setPage: (n: number) => void }) {
  return (
    <div className="pager">
      <span>{data.total.toLocaleString()} records · page {page} of {Math.max(1, Math.ceil(data.total / data.page_size))}</span>
      <div>
        <button disabled={page === 1} onClick={() => setPage(page - 1)}>Previous</button>
        <button disabled={page * data.page_size >= data.total} onClick={() => setPage(page + 1)}>Next</button>
      </div>
    </div>
  );
}

export function EventTable({ items }: { items: Data[] }) {
  return !items.length ? <Empty /> : (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Event time</th>
            <th>Identity</th>
            <th>Producing computer</th>
            <th>Activity / path</th>
            <th>Outcome</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {items.map(e => (
            <tr key={e.id}>
              <td><Time value={e.time} /></td>
              <td>{e.account || e.user_sid || 'Unknown user'}</td>
              <td>{e.source_computer}<small>{e.channel} · {e.event_id || '—'}</small></td>
              <td>
                <span className="capitalize">
                  {e.category === 'file_copy' && /^[D-Z]:/i.test(e.object_path || '')
                    ? 'File pasted to USB pen drive'
                    : e.category === 'sign_in' && e.result === 'denied'
                    ? 'Failed sign-in (wrong password)'
                    : e.category.replaceAll('_', ' ')}
                </span>
                <small className="path" title={e.object_path}>{e.object_path || 'No path supplied'}</small>
              </td>
              <td><Badge tone={e.result}>{e.result}</Badge></td>
              <td><Link aria-label="Open event" to={'/events/' + e.id}><ChevronRight size={18} /></Link></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function AlertList({ items }: { items: Data[] }) {
  return !items.length ? (
    <Empty title="No alert findings">
      No detections were recorded in this period. Verify collection coverage before interpreting an empty result.
    </Empty>
  ) : (
    <div className="alert-list">
      {items.map(a => (
        <Link to={'/alerts/' + a.id} className="alert-row" key={a.id}>
          <Badge tone={a.severity}>{a.severity}</Badge>
          <div>
            <strong>{a.title}</strong>
            <small>{a.account || a.user_sid || 'Unknown identity'} · {a.kind === 'model' ? 'Model finding' : 'Detection rule'}</small>
            <small><Time value={a.last_time} /></small>
          </div>
          <Badge tone={a.status}>{a.status}</Badge>
          <ChevronRight size={17} />
        </Link>
      ))}
    </div>
  );
}

export function Chart({ rows, keyName = 'count', color = '#307ae8' }: { rows: Data[]; keyName?: string; color?: string }) {
  return rows.length ? (
    <div className="chart">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={rows}>
          <CartesianGrid strokeDasharray="3 5" vertical={false} />
          <XAxis dataKey="time" tickFormatter={s => String(s).slice(11, 16)} minTickGap={35} />
          <YAxis width={35} />
          <Tooltip />
          <Area type="monotone" dataKey={keyName} stroke={color} strokeWidth={2} fill={color} fillOpacity={0.1} isAnimationActive={false} />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  ) : <Empty title="Awaiting measured activity">The chart starts with your first collected record.</Empty>;
}

export function JsonEditor({ value, save }: { value: any; save: (v: any) => Promise<any> }) {
  const [text, setText] = useState(JSON.stringify(value, null, 2));
  const [err, setErr] = useState('');
  const [state, setState] = useState('');
  return (
    <form className="stack" onSubmit={async e => {
      e.preventDefault();
      setState('Saving…');
      try {
        await save(JSON.parse(text));
        setErr('');
        setState('Saved');
      } catch (e: any) {
        setErr(e.message);
        setState('');
      }
    }}>
      <textarea className="code-editor" aria-label="JSON configuration" spellCheck={false} rows={15} value={text} onChange={e => setText(e.target.value)} />
      <ErrorBox message={err} />
      <div className="actions">
        <button className="primary" disabled={state === 'Saving…'}>Save configuration</button>
        <span>{state}</span>
      </div>
    </form>
  );
}

export function Facts({ items }: { items: any[][] }) {
  return <div className="facts">{items.map(([k, v]) => <div key={k}><small>{k}</small><span>{v ?? 'Unknown'}</span></div>)}</div>;
}

export function formatBytes(bytes?: number | null, unit: 'GiB' | 'GB' = 'GiB'): string {
  if (bytes == null || isNaN(bytes)) return 'Unavailable';
  const factor = unit === 'GiB' ? 1024 * 1024 * 1024 : 1000 * 1000 * 1000;
  return (bytes / factor).toFixed(2) + ' ' + unit;
}

export function timeAgo(iso?: string | null): string {
  if (!iso) return 'Not received';
  const diffSec = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
  if (diffSec < 0) return 'Just now';
  if (diffSec < 60) return `${diffSec} seconds ago`;
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin} min ago`;
  const diffHours = Math.floor(diffMin / 60);
  if (diffHours < 24) return `${diffHours} hours ago`;
  const diffDays = Math.floor(diffHours / 24);
  return `${diffDays} days ago`;
}

export function computePresence(lastHeartbeat?: string | null): 'Online' | 'Stale' | 'Offline' | 'Unknown' {
  if (!lastHeartbeat) return 'Unknown';
  const age = Math.floor((Date.now() - new Date(lastHeartbeat).getTime()) / 1000);
  if (age < 0) return 'Unknown';
  if (age < 60) return 'Online';
  if (age <= 180) return 'Stale';
  return 'Offline';
}

export function HealthBar({ percent, color = '#38bdf8' }: { percent?: number | null; color?: string }) {
  const p = percent == null ? 0 : Math.max(0, Math.min(100, Math.round(percent)));
  return (
    <div className="health-bar-track">
      <div className="health-bar-fill" style={{ width: `${p}%`, backgroundColor: color }} />
    </div>
  );
}
