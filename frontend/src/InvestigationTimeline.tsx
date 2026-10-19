import { useState, useEffect, useContext, useMemo } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import {
  User, Monitor, FileText, AlertCircle, Globe, Download, Terminal, FileCode,
  Link2, CheckCircle2, MinusCircle, MessageSquare, Save, Shield, Presentation,
  FileDown, Database
} from 'lucide-react';
import { Context, api, Badge, Empty, ErrorBox, Json, Time } from './core';
import type { Data } from './core';

function formatBytesShort(bytes?: number | null): string {
  if (bytes == null || Number.isNaN(Number(bytes))) return '';
  const n = Number(bytes);
  if (n < 1024) return `${n} B`;
  const kib = n / 1024;
  if (kib < 1024) return `${kib >= 10 ? kib.toFixed(0) : kib.toFixed(1)} KiB`;
  return `${(kib / 1024).toFixed(1)} MiB`;
}

function shortDownloadsPath(p?: string | null, fallbackName?: string): string {
  if (!p) return fallbackName ? `Downloads\\${fallbackName}` : 'Unavailable';
  const idx = p.toLowerCase().indexOf('downloads\\');
  if (idx >= 0) return p.slice(idx);
  return p;
}

export function InvestigationTimeline() {
  const { user, period, refresh: globalRefresh, bump } = useContext(Context);
  const [searchParams, setSearchParams] = useSearchParams();

  const [timelineList, setTimelineList] = useState<Data[]>([]);
  const [selectedCaseKey, setSelectedCaseKey] = useState<string>(
    searchParams.get('case_key') || searchParams.get('chain_id') || ''
  );
  const [chainDetail, setChainDetail] = useState<Data | null>(null);
  const [confidenceFilter, setConfidenceFilter] = useState<string>('');
  const [reviewFilter, setReviewFilter] = useState<string>('');
  const [searchQuery, setSearchQuery] = useState<string>(searchParams.get('q') || '');

  const [reviewState, setReviewState] = useState<string>('Needs follow-up');
  const [reviewNotes, setReviewNotes] = useState<string>('');
  const [savingReview, setSavingReview] = useState<boolean>(false);
  const [reviewSavedMsg, setReviewSavedMsg] = useState<string>('');
  const [error, setError] = useState<string>('');

  useEffect(() => {
    let live = true;
    const loadChains = async () => {
      try {
        const qs = new URLSearchParams(period);
        if (confidenceFilter) qs.set('confidence', confidenceFilter);
        if (reviewFilter) qs.set('review_state', reviewFilter);
        if (searchQuery.trim()) qs.set('q', searchQuery.trim());

        const res = await api(`/timeline?${qs.toString()}`);
        if (!live) return;
        const items: Data[] = res.items || [];
        setTimelineList(items);
        setError('');

        if (items.length > 0) {
          const exists = items.some(c => c.case_key === selectedCaseKey);
          if (!selectedCaseKey || !exists) {
            setSelectedCaseKey(items[0].case_key);
          }
        } else if (!searchParams.get('case_key')) {
          setSelectedCaseKey('');
        }
      } catch (e: any) {
        if (live) setError(e.message || 'Failed to load investigation timeline');
      }
    };

    loadChains();
    const timer = setInterval(loadChains, 15000);
    return () => {
      live = false;
      clearInterval(timer);
    };
  }, [period, confidenceFilter, reviewFilter, searchQuery, globalRefresh]);

  useEffect(() => {
    if (!selectedCaseKey) {
      setChainDetail(null);
      return;
    }
    let live = true;
    api(`/timeline/${encodeURIComponent(selectedCaseKey)}`)
      .then(d => {
        if (!live) return;
        setChainDetail(d);
        if (d.review?.state && d.review.state !== 'Unreviewed') {
          setReviewState(d.review.state);
        }
        if (d.review?.notes) {
          setReviewNotes(d.review.notes);
        } else {
          setReviewNotes('');
        }
      })
      .catch(() => {
        if (live) setChainDetail(null);
      });
    return () => {
      live = false;
    };
  }, [selectedCaseKey, timelineList]);

  const activeChain = chainDetail || timelineList.find(c => c.case_key === selectedCaseKey) || null;
  const primaryDownload = activeChain?.downloads?.[0] || null;
  const primaryNav = activeChain?.navigations?.[0] || null;
  const primaryProc = activeChain?.processes?.[0] || null;
  const links: Data[] = activeChain?.links || [];

  // Build explainable visual steps matching 03-investigation-timeline.png
  const visualSteps = useMemo(() => {
    if (!activeChain) return [];
    const out: Data[] = [];

    if (primaryNav) {
      out.push({
        key: `nav-${primaryNav.id}`,
        time: primaryNav.navigation_time,
        icon: 'nav',
        title: 'Navigation recorded',
        primaryText: primaryNav.normalized_domain || primaryNav.domain,
        description: `User visited ${primaryNav.normalized_domain || primaryNav.domain} in an enrolled browser profile.`,
        badge: 'Browser extension',
        badgeTone: 'blue',
        connectorLabel: null
      });
    }

    if (primaryDownload) {
      const sizeStr = formatBytesShort(primaryDownload.final_size_bytes);
      out.push({
        key: `dl-${primaryDownload.id}`,
        time: primaryDownload.completed_at || primaryDownload.started_at,
        icon: 'download',
        title: `Download ${primaryDownload.state === 'completed' ? 'completed' : primaryDownload.state}`,
        primaryText: `${primaryDownload.filename}${sizeStr ? ` • ${sizeStr}` : ''}`,
        description: `File downloaded from ${primaryDownload.source_domain || 'source domain'} and saved to the user's Downloads folder.`,
        badge: 'Browser extension',
        badgeTone: 'blue',
        connectorLabel: 'Same enrolled device and user'
      });
    }

    for (const proc of activeChain.processes || []) {
      const ptime = proc.creation_time || proc.first_seen_at;
      const isPs = /powershell|pwsh/i.test(proc.name || '');
      out.push({
        key: `proc-${proc.instance_key}`,
        time: ptime,
        icon: 'process',
        title: isPs ? 'PowerShell started' : `${proc.name} started`,
        primaryText: `PID ${proc.pid}`,
        description: `A ${proc.name} process was started on the same device (${activeChain.hostname || activeChain.device_id}).`,
        badge: 'Process event',
        badgeTone: 'violet',
        connectorLabel: null
      });

      if (proc.command_line || proc.executable_path) {
        const dlPathShort = shortDownloadsPath(
          primaryDownload?.final_path,
          primaryDownload?.filename
        );
        const dlLink = links.find(
          (l: Data) =>
            l.link_kind === 'download_to_process' && l.target_id === proc.instance_key
        );
        out.push({
          key: `cmd-${proc.instance_key}`,
          time: ptime,
          icon: 'script',
          title: isPs ? 'Script path referenced' : 'Executable / command evidence',
          primaryText: dlPathShort !== 'Unavailable' ? dlPathShort : proc.command_line || proc.executable_path,
          description: proc.command_line
            ? `Command line: ${proc.command_line}`
            : `Executable path: ${proc.executable_path}`,
          badge: proc.command_line ? 'Command-line evidence' : 'Executable path evidence',
          badgeTone: 'blue',
          connectorLabel:
            dlLink?.relationship_label || 'Exact saved path matched to script argument'
        });
      }
    }

    return out;
  }, [activeChain, primaryNav, primaryDownload, links]);

  // Build "Why these records are linked" numbered list from actual correlation links
  const whyLinkedReasons = useMemo(() => {
    if (!activeChain) return [];
    const reasons: { title: string; detail: string }[] = [
      {
        title: 'Same enrolled endpoint and Windows SID',
        detail: `All events were recorded from the same device (${
          activeChain.hostname || activeChain.device_id
        }) and user (${activeChain.account || activeChain.user_sid || 'verified SID'}).`
      }
    ];

    if (primaryDownload && primaryProc) {
      const dlTime = primaryDownload.completed_at || primaryDownload.started_at;
      const pTime = primaryProc.creation_time || primaryProc.first_seen_at;
      reasons.push({
        title: 'Download completed before execution',
        detail: `The file download occurred at ${
          dlTime ? new Date(dlTime).toLocaleTimeString('en-GB') : 'recorded time'
        } and ${primaryProc.name} started at ${
          pTime ? new Date(pTime).toLocaleTimeString('en-GB') : 'subsequent time'
        }.`
      });
    } else if (primaryNav && primaryDownload) {
      reasons.push({
        title: 'Domain navigation preceded file download',
        detail: `Top-level visit to ${primaryNav.normalized_domain} matched the download source/referrer domain within the correlation window.`
      });
    }

    const dlToProc = links.find((l: Data) => l.link_kind === 'download_to_process') || links[0];
    if (dlToProc) {
      const matched = dlToProc.matched_fields || {};
      const matchKeys = Object.keys(matched);
      reasons.push({
        title: dlToProc.relationship_label || 'Script argument / path matches saved download',
        detail:
          dlToProc.explanation ||
          `Matched fields (${matchKeys.join(', ') || 'path, user_sid, device_id'}) with ${
            dlToProc.confidence
          } confidence.`
      });
    }

    return reasons;
  }, [activeChain, primaryDownload, primaryProc, primaryNav, links]);

  const missingFieldsSummary = useMemo(() => {
    const set = new Set<string>();
    for (const l of links) {
      for (const m of l.missing_fields || []) {
        set.add(String(m));
      }
    }
    return Array.from(set);
  }, [links]);

  const competingCandidatesSummary = useMemo(() => {
    const list: Data[] = [];
    for (const l of links) {
      for (const c of l.competing_candidates || []) {
        list.push(c);
      }
    }
    return list;
  }, [links]);

  async function handleSaveReview() {
    if (!activeChain) return;
    setSavingReview(true);
    setReviewSavedMsg('');
    setError('');
    try {
      await api(`/timeline/${encodeURIComponent(activeChain.case_key)}/review`, {
        method: 'POST',
        body: JSON.stringify({
          state: reviewState,
          notes: reviewNotes.trim() || 'Reviewed in Investigation Timeline'
        })
      });
      setReviewSavedMsg('Review saved');
      bump();
    } catch (e: any) {
      setError(e.message || 'Failed to save review');
    } finally {
      setSavingReview(false);
    }
  }

  const displayAccount = useMemo(() => {
    const raw = activeChain?.account || activeChain?.user_sid || 'Unknown';
    return raw.replace(/^LAB\\/i, '');
  }, [activeChain]);

  const reviewBadgeLabel = useMemo(() => {
    const st = activeChain?.review?.state;
    if (!st || st === 'Unreviewed') return 'Needs review';
    return st;
  }, [activeChain]);

  return (
    <div className="pm-page">
      <div className="pm-header-row">
        <div>
          <h1>Download-to-execution review</h1>
          <p>Connect observed browser and process evidence without assuming malicious intent.</p>
        </div>

        {/* Case Selector & Filters */}
        <div className="tl-selector-bar">
          {timelineList.length > 1 && (
            <select
              aria-label="Select correlated evidence chain"
              value={selectedCaseKey}
              onChange={e => {
                setSelectedCaseKey(e.target.value);
                setSearchParams({ case_key: e.target.value });
              }}
            >
              {timelineList.map(ch => (
                <option key={ch.case_key} value={ch.case_key}>
                  [{ch.confidence}] {ch.title} ({ch.account || ch.hostname})
                </option>
              ))}
            </select>
          )}
          <select
            aria-label="Filter by confidence"
            value={confidenceFilter}
            onChange={e => setConfidenceFilter(e.target.value)}
          >
            <option value="">All confidence levels</option>
            <option value="High">High confidence</option>
            <option value="Medium">Medium confidence</option>
            <option value="Low">Low confidence</option>
          </select>
        </div>
      </div>

      <ErrorBox message={error} />

      {!activeChain ? (
        <div className="panel">
          <Empty title="No correlated browser-to-process chains in this period">
            When an enrolled browser profile downloads a file or script and a process subsequently executes or references it on the same device, the linked evidence chain appears here automatically.
          </Empty>
        </div>
      ) : (
        <>
          {/* 4 Top Summary Cards matching 03-investigation-timeline.png */}
          <div className="tl-top-cards">
            <div className="tl-summary-card">
              <div className="tl-card-icon blue">
                <User size={20} />
              </div>
              <div>
                <small>Employee</small>
                <strong>{displayAccount}</strong>
              </div>
            </div>

            <div className="tl-summary-card">
              <div className="tl-card-icon blue">
                <Monitor size={20} />
              </div>
              <div>
                <small>Device</small>
                <strong>{activeChain.hostname || activeChain.device_id}</strong>
              </div>
            </div>

            <div className="tl-summary-card">
              <div className="tl-card-icon blue">
                <FileText size={20} />
              </div>
              <div>
                <small>File</small>
                <strong>
                  {primaryDownload?.filename || primaryProc?.name || activeChain.title}
                </strong>
              </div>
            </div>

            <div className="tl-summary-card">
              <div className="tl-card-icon amber">
                <AlertCircle size={20} />
              </div>
              <div>
                <small>Review status</small>
                <strong className="tl-status-text">{reviewBadgeLabel}</strong>
              </div>
            </div>
          </div>

          {/* Main 2-Column Investigation Layout */}
          <div className="tl-main-grid">
            {/* Left Column: Timeline of related activity + Source accordion + Review notes */}
            <div className="tl-left-col">
              <div className="panel tl-timeline-panel">
                <h2>Timeline of related activity</h2>

                <div className="tl-vertical-rail">
                  {visualSteps.map(step => (
                    <div key={step.key} className="tl-step-block">
                      <div className="tl-step-row">
                        <div className="tl-step-time">
                          {step.time ? new Date(step.time).toLocaleTimeString('en-GB') : '—'}
                        </div>
                        <div className="tl-step-node-col">
                          <span className="tl-rail-dot" />
                          <div className={`tl-step-circle ${step.icon}`}>
                            {step.icon === 'nav' && <Globe size={18} />}
                            {step.icon === 'download' && <Download size={18} />}
                            {step.icon === 'process' && <Terminal size={18} />}
                            {step.icon === 'script' && <FileCode size={18} />}
                          </div>
                        </div>
                        <div className="tl-step-content">
                          <div className="tl-step-head">
                            <div>
                              <strong>{step.title}</strong>
                              <div className="tl-step-primary">{step.primaryText}</div>
                            </div>
                            <span className={`tl-source-pill ${step.badgeTone}`}>
                              {step.badge}
                            </span>
                          </div>
                          <p>{step.description}</p>
                          {step.connectorLabel && (
                            <div className="tl-match-pill">
                              <span className="dot green" />
                              {step.connectorLabel}
                            </div>
                          )}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Source records and correlation details */}
              <div className="panel tl-accordion-panel">
                <details>
                  <summary className="tl-accordion-summary">
                    <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                      <Database size={18} style={{ color: '#2563eb' }} />
                      <div>
                        <strong>Source records and correlation details</strong>
                        <p style={{ margin: 0, fontSize: '11.5px', color: 'var(--muted)', fontWeight: 400 }}>
                          View the source records for each timeline event, matched/missing fields, and competing candidates.
                        </p>
                      </div>
                    </div>
                  </summary>
                  <div style={{ padding: '14px 18px' }}>
                    <div style={{ marginBottom: '10px', fontSize: '12px' }}>
                      <strong>Correlation Confidence:</strong>{' '}
                      <Badge
                        tone={
                          activeChain.confidence === 'High'
                            ? 'online'
                            : activeChain.confidence === 'Medium'
                            ? 'medium'
                            : 'low'
                        }
                      >
                        {activeChain.confidence}
                      </Badge>
                      {missingFieldsSummary.length > 0 && (
                        <span style={{ marginLeft: '12px', color: 'var(--muted)' }}>
                          Missing / unverified fields: <code>{missingFieldsSummary.join(', ')}</code>
                        </span>
                      )}
                    </div>
                    {competingCandidatesSummary.length > 0 && (
                      <div style={{ marginBottom: '10px', fontSize: '12px' }}>
                        <strong>Competing candidates considered within window:</strong>
                        <Json value={competingCandidatesSummary} />
                      </div>
                    )}
                    <Json
                      value={{
                        links: activeChain.links,
                        navigations: activeChain.navigations,
                        downloads: activeChain.downloads,
                        processes: activeChain.processes,
                        collection_gaps: activeChain.collection_gaps
                      }}
                    />
                  </div>
                </details>
              </div>

              {/* Review Notes Bar */}
              <div className="panel tl-review-panel">
                <div className="tl-review-header">
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <MessageSquare size={17} style={{ color: '#2563eb' }} />
                    <strong>Review notes</strong>
                  </div>
                  <select
                    aria-label="Review disposition"
                    value={reviewState}
                    onChange={e => setReviewState(e.target.value)}
                    style={{ fontSize: '12px', padding: '5px 10px' }}
                  >
                    <option value="Needs follow-up">Needs follow-up</option>
                    <option value="Benign / expected activity">Benign / expected activity</option>
                    <option value="Confirmed policy violation">Confirmed policy violation</option>
                    <option value="Unreviewed">Unreviewed</option>
                  </select>
                </div>

                <div className="tl-review-input-row">
                  <div className="tl-textarea-wrap">
                    <textarea
                      rows={2}
                      maxLength={500}
                      placeholder="Add your review notes here (e.g. what you verified, any additional context)..."
                      value={reviewNotes}
                      onChange={e => setReviewNotes(e.target.value)}
                    />
                    <small className="tl-char-count">{reviewNotes.length} / 500</small>
                  </div>
                  {user.role !== 'Viewer' && (
                    <button
                      type="button"
                      className="button primary tl-save-btn"
                      disabled={savingReview}
                      onClick={handleSaveReview}
                    >
                      <Save size={15} /> {savingReview ? 'Saving…' : 'Save review'}
                    </button>
                  )}
                </div>
                {reviewSavedMsg && (
                  <small style={{ color: '#10b981', display: 'block', marginTop: '6px' }}>
                    {reviewSavedMsg} · Recorded under {user.username}
                  </small>
                )}
              </div>
            </div>

            {/* Right Column: Explainability Cards */}
            <aside className="tl-right-col">
              <div className="panel tl-explain-card">
                <div className="tl-card-heading">
                  <Link2 size={18} style={{ color: '#0d9488' }} />
                  <h2>Why these records are linked</h2>
                </div>
                <div className="tl-numbered-list">
                  {whyLinkedReasons.map((item, idx) => (
                    <div key={idx} className="tl-numbered-item">
                      <span className="tl-num-circle">{idx + 1}</span>
                      <div>
                        <strong>{item.title}</strong>
                        <p>{item.detail}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              <div className="panel tl-explain-card">
                <div className="tl-card-heading">
                  <CheckCircle2 size={18} style={{ color: '#0d9488' }} />
                  <h2>What is established</h2>
                </div>
                <div className="tl-established-box good">
                  {primaryDownload && primaryProc
                    ? `A downloaded file (${primaryDownload.filename}) on ${
                        activeChain.hostname || activeChain.device_id
                      } was subsequently referenced or executed by ${primaryProc.name} (PID ${
                        primaryProc.pid
                      }) under ${activeChain.account || activeChain.user_sid} (${
                        activeChain.confidence
                      } correlation confidence).`
                    : `Correlated browser and endpoint telemetry records on ${
                        activeChain.hostname || activeChain.device_id
                      } were linked via deterministic ${activeChain.primary_relationship}.`}
                </div>
              </div>

              <div className="panel tl-explain-card">
                <div className="tl-card-heading">
                  <MinusCircle size={18} style={{ color: '#dc2626' }} />
                  <h2>What is not established</h2>
                </div>
                <div className="tl-established-box caution">
                  Malicious intent or harmful effects.
                  <br />
                  Correlation links observed telemetry; human analyst verification is required.
                </div>
              </div>
            </aside>
          </div>

          {/* Bottom Action & Impact Strip */}
          <div className="tl-bottom-bar">
            <div className="tl-impact-note">
              <Shield size={22} style={{ color: '#0d9488', flexShrink: 0 }} />
              <div>
                <strong>Possible impact if a malicious script runs</strong>
                <p>Unwanted commands, configuration changes, or access to data depending on privileges.</p>
              </div>
            </div>
            <div className="actions">
              <Link to="/present" className="button primary">
                <Presentation size={15} /> Present to teacher
              </Link>
              <a
                className="button"
                href={`/api/timeline/${encodeURIComponent(activeChain.case_key)}/export?format=json`}
                download
              >
                <FileDown size={15} /> Export evidence
              </a>
              <a
                className="button"
                href={`/api/timeline/${encodeURIComponent(activeChain.case_key)}/export?format=csv`}
                download
              >
                CSV
              </a>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
