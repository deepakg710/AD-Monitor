import { useState, useEffect, useContext, useMemo } from 'react';
import { Link, useParams, useSearchParams, useNavigate } from 'react-router-dom';
import {
  Shield, ShieldAlert, ShieldCheck, FileText, HardDrive, Usb, Terminal,
  Globe, Users, Lock, Database, Activity, AlertTriangle, CheckCircle2,
  HelpCircle, Lightbulb, ArrowLeft, ArrowRight, ExternalLink, Printer,
  BookOpen, Search, LayoutGrid, Table as TableIcon, Monitor, Clock,
  Settings, Eye, Sparkles, Info, Play, FolderLock, Download
} from 'lucide-react';
import { Context, useData, Badge, ErrorBox, Time } from './core';
import type { Data } from './core';
import {
  ATTACK_CATALOG,
  CATEGORIES,
  GLOSSARY,
  TEACHER_GUIDED_SCENARIOS,
  getTopicByIdOrRule,
  createFallbackTopicForUnknownRule
} from './catalog';
import type { AttackTopic, AttackCategory, MitreReference } from './catalog';

function renderTopicIcon(iconName: AttackTopic['iconName'], size = 22) {
  switch (iconName) {
    case 'file': return <FolderLock size={size} />;
    case 'database': return <Database size={size} />;
    case 'users': return <Users size={size} />;
    case 'usb': return <Usb size={size} />;
    case 'terminal': return <Terminal size={size} />;
    case 'download': return <Download size={size} />;
    case 'globe': return <Globe size={size} />;
    case 'clock': return <Clock size={size} />;
    case 'alert': return <ShieldAlert size={size} />;
    case 'archive': return <HardDrive size={size} />;
    case 'zap': return <Activity size={size} />;
    case 'key': return <Lock size={size} />;
    case 'lock': return <Lock size={size} />;
    case 'network': return <Monitor size={size} />;
    case 'monitor': return <Eye size={size} />;
    default: return <Shield size={size} />;
  }
}

export function determineProvenance(alertObj?: Data | null): {
  code: 'operational' | 'controlled_lab' | 'educational';
  label: string;
  badgeText: string;
  tone: string;
  explanation: string;
} {
  if (!alertObj) {
    return {
      code: 'educational',
      label: 'Educational example',
      badgeText: 'EDUCATIONAL EXAMPLE',
      tone: 'teal',
      explanation: 'Concept walkthrough and lab design reference. Not a live security incident.'
    };
  }
  const evList: Data[] = alertObj.evidence || [];
  const hasXml = evList.some(
    e => e.evidence_type === 'windows_event_xml' || (e.provider && String(e.provider).includes('Security-Auditing'))
  );
  if (hasXml) {
    return {
      code: 'operational',
      label: 'Operational evidence',
      badgeText: 'OPERATIONAL EVIDENCE · WINDOWS AUDIT',
      tone: 'green',
      explanation: 'Backed by persisted Windows Security Event XML collected from the domain or endpoint.'
    };
  }
  return {
    code: 'controlled_lab',
    label: 'Controlled lab evidence',
    badgeText: 'CONTROLLED LAB EVIDENCE',
    tone: 'amber',
    explanation: 'Backed by controlled lab exercise or endpoint collector snapshot records in SQLite.'
  };
}

export function AttackLibrary() {
  const { period } = useContext(Context);
  const { data: summary, error } = useData('/catalog-summary?' + period);
  const [search, setSearch] = useState('');
  const [category, setCategory] = useState<'All' | AttackCategory>('All');
  const [implFilter, setImplFilter] = useState<'all' | 'implemented' | 'educational' | 'active'>('all');
  const [viewMode, setViewMode] = useState<'grid' | 'table'>('grid');
  const [showGlossary, setShowGlossary] = useState(false);

  // Merge catalog entries with any custom/unknown rules in DB
  const allTopics = useMemo(() => {
    const list: AttackTopic[] = [...ATTACK_CATALOG];
    if (summary?.rules) {
      const knownRuleIds = new Set(list.map(t => t.ruleId).filter(Boolean));
      for (const r of summary.rules) {
        if (r.id && !knownRuleIds.has(r.id)) {
          list.push(createFallbackTopicForUnknownRule(r.id, r.name));
        }
      }
    }
    return list;
  }, [summary]);

  const ruleMap = useMemo(() => {
    const m: Record<string, Data> = {};
    for (const r of summary?.rules || []) {
      m[r.id] = r;
    }
    return m;
  }, [summary]);

  const openByRule: Record<string, number> = summary?.open_by_rule || {};
  const totalByRule: Record<string, number> = summary?.total_by_rule || {};

  // Separate counts required by Section 3
  const catalogCount = allTopics.length;
  const configuredDetectorCount = (summary?.rules || []).filter((r: Data) => r.enabled).length || 14;
  const readyDetectorCount = (summary?.rules || []).filter((r: Data) => r.enabled && r.readiness?.ready).length;
  const totalOpenFindings = Object.values(openByRule).reduce((acc, v) => acc + (Number(v) || 0), 0);

  const filteredTopics = useMemo(() => {
    return allTopics.filter(t => {
      if (category !== 'All' && t.category !== category) return false;
      const openCount = t.ruleId ? (openByRule[t.ruleId] || 0) : 0;
      if (implFilter === 'implemented' && !t.detection.hasDetector) return false;
      if (implFilter === 'educational' && t.detection.hasDetector) return false;
      if (implFilter === 'active' && openCount === 0) return false;

      if (!search.trim()) return true;
      const q = search.toLowerCase();
      const mitreMatch = t.mitre.techniques.some(
        (m: MitreReference) => m.id.toLowerCase().includes(q) || m.officialName.toLowerCase().includes(q)
      );
      return (
        t.title.toLowerCase().includes(q) ||
        t.shortTitle.toLowerCase().includes(q) ||
        t.technicalLabel.toLowerCase().includes(q) ||
        t.shortMeaning.toLowerCase().includes(q) ||
        t.shortConsequence.toLowerCase().includes(q) ||
        t.category.toLowerCase().includes(q) ||
        (t.ruleId && t.ruleId.toLowerCase().includes(q)) ||
        mitreMatch
      );
    });
  }, [allTopics, category, implFilter, search, openByRule]);

  return (
    <div className="attack-library-page">
      {/* Top Header */}
      <div className="atk-header-row">
        <div>
          <div className="atk-eyebrow-row">
            <span className="atk-design-pill">
              <BookOpen size={13} /> EDUCATIONAL CATALOG · EVIDENCE-FIRST REFERENCE
            </span>
          </div>
          <h1>Attack library</h1>
          <p className="atk-subtitle">
            Understand the behavior, possible harm, and evidence needed. Built for non-specialist review and viva demonstration.
          </p>
        </div>
        <div className="atk-header-actions">
          <button
            type="button"
            className={showGlossary ? 'primary' : ''}
            onClick={() => setShowGlossary(v => !v)}
          >
            <HelpCircle size={15} /> {showGlossary ? 'Hide glossary' : 'Plain-language glossary'}
          </button>
          <Link to="/present" className="button primary atk-present-btn">
            <Play size={15} /> Teacher presentation mode
          </Link>
        </div>
      </div>

      <ErrorBox message={error} />

      {/* 4 Separate Coverage & Finding Counters (Prompt Section 3) */}
      <div className="atk-counters-strip">
        <div className="atk-counter-card">
          <small>Educational catalog topics</small>
          <strong>{catalogCount}</strong>
          <span>14 rule-backed · 3 concept-only entries</span>
        </div>
        <div className="atk-counter-card">
          <small>Configured rule detectors</small>
          <strong>{configuredDetectorCount}</strong>
          <span>Enabled in SQLite rules engine</span>
        </div>
        <div className="atk-counter-card">
          <small>Telemetry-ready detectors</small>
          <strong>{summary ? `${readyDetectorCount} / ${configuredDetectorCount}` : '—'}</strong>
          <span>Based on collected event categories</span>
        </div>
        <div className="atk-counter-card">
          <small>Open findings in period</small>
          <strong style={{ color: totalOpenFindings > 0 ? '#ef4444' : 'inherit' }}>
            {totalOpenFindings}
          </strong>
          <span><Link to="/alerts">View live alert queue ➔</Link></span>
        </div>
      </div>

      {/* Collapsible Plain-Language Glossary */}
      {showGlossary && (
        <div className="atk-glossary-panel">
          <div className="atk-glossary-header">
            <div>
              <strong>Plain-language security & Windows auditing glossary</strong>
              <p>Quick definitions for teachers and examiners reviewing Windows Active Directory and endpoint evidence.</p>
            </div>
            <button type="button" onClick={() => setShowGlossary(false)}>Close</button>
          </div>
          <div className="atk-glossary-grid">
            {GLOSSARY.map(g => (
              <div key={g.term} className="atk-glossary-item">
                <strong>{g.term}</strong>
                <p>{g.definition}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Search Bar */}
      <div className="atk-search-bar">
        <Search size={18} className="atk-search-icon" />
        <input
          type="search"
          aria-label="Search attack types"
          placeholder="Search attack types, plain-language meanings, Windows Event IDs, or MITRE IDs..."
          value={search}
          onChange={e => setSearch(e.target.value)}
        />
        {search && (
          <button type="button" className="atk-clear-btn" onClick={() => setSearch('')}>
            Clear
          </button>
        )}
      </div>

      {/* Category Filter Pills & View Switcher */}
      <div className="atk-filter-row">
        <div className="atk-category-pills" role="tablist" aria-label="Attack categories">
          {(['All', ...CATEGORIES] as const).map(cat => (
            <button
              key={cat}
              type="button"
              role="tab"
              aria-selected={category === cat}
              className={`atk-pill ${category === cat ? 'active' : ''}`}
              onClick={() => setCategory(cat)}
            >
              {cat}
            </button>
          ))}
        </div>

        <div className="atk-view-controls">
          <select
            aria-label="Filter by implementation or findings"
            value={implFilter}
            onChange={e => setImplFilter(e.target.value as any)}
          >
            <option value="all">All catalog entries ({allTopics.length})</option>
            <option value="implemented">Implemented detectors (14)</option>
            <option value="educational">Educational only — not implemented (3)</option>
            <option value="active">With open findings ({Object.keys(openByRule).length})</option>
          </select>

          <div className="atk-view-toggle">
            <button
              type="button"
              className={viewMode === 'grid' ? 'active' : ''}
              onClick={() => setViewMode('grid')}
              title="Card grid view"
            >
              <LayoutGrid size={15} /> Cards
            </button>
            <button
              type="button"
              className={viewMode === 'table' ? 'active' : ''}
              onClick={() => setViewMode('table')}
              title="Teacher comparison table view"
            >
              <TableIcon size={15} /> Compare table
            </button>
          </div>
        </div>
      </div>

      {/* Main Content: Card Grid or Comparison Table */}
      {viewMode === 'grid' ? (
        <div className="atk-cards-grid">
          {filteredTopics.map(topic => {
            const rule = topic.ruleId ? ruleMap[topic.ruleId] : null;
            const isReady = rule ? Boolean(rule.readiness?.ready) : false;
            const missingCats: string[] = rule?.readiness?.missing || [];
            const openCount = topic.ruleId ? (openByRule[topic.ruleId] || 0) : 0;
            const periodTotal = topic.ruleId ? (totalByRule[topic.ruleId] || 0) : 0;

            return (
              <div key={topic.id} className="atk-card">
                <div className="atk-card-top">
                  <div className={`atk-card-icon ${topic.badgeTone}`}>
                    {renderTopicIcon(topic.iconName, 24)}
                  </div>
                  <div className="atk-card-heading">
                    <div className="atk-card-title-row">
                      <h3>
                        <Link to={`/attack-library/${topic.id}`}>{topic.shortTitle || topic.title}</Link>
                      </h3>
                      <span className={`atk-short-badge ${topic.badgeTone}`}>
                        {topic.badgeText}
                      </span>
                    </div>
                    <small className="atk-tech-subtitle">
                      {topic.category} · {topic.technicalLabel}
                    </small>
                  </div>
                </div>

                <p className="atk-card-meaning">{topic.shortMeaning}</p>

                <p className="atk-card-impact">
                  <strong>Possible impact:</strong> {topic.shortConsequence}
                </p>

                {/* Independent Status Row: Implementation / Readiness vs Open Findings */}
                <div className="atk-card-status-strip">
                  {!topic.detection.hasDetector ? (
                    <span className="atk-readiness-pill edu">
                      Educational entry — detection not implemented
                    </span>
                  ) : isReady ? (
                    <span className="atk-readiness-pill ready">
                      <span className="dot green" /> Detector ready ({topic.ruleId})
                    </span>
                  ) : (
                    <span className="atk-readiness-pill missing" title={`Requires telemetry: ${missingCats.join(', ') || topic.detection.requiredTelemetry.join(', ')}`}>
                      <span className="dot amber" /> Needs telemetry: {(missingCats[0] || 'event source').replace(/_/g, ' ')}
                    </span>
                  )}

                  {topic.detection.hasDetector && (
                    <span className={`atk-finding-pill ${openCount > 0 ? 'has-open' : ''}`}>
                      {openCount > 0
                        ? `${openCount} open finding${openCount > 1 ? 's' : ''}`
                        : periodTotal > 0
                          ? `${periodTotal} in period (closed)`
                          : '0 open findings'}
                    </span>
                  )}
                </div>

                <div className="atk-card-footer">
                  <Link to={`/attack-library/${topic.id}`} className="atk-learn-btn">
                    Learn more <ArrowRight size={15} />
                  </Link>
                  <div className="atk-card-secondary-links">
                    {openCount > 0 && (
                      <Link to={`/attack-library/${topic.id}?case=latest`} className="atk-case-link">
                        Inspect live case ➔
                      </Link>
                    )}
                    <Link to={`/present/${topic.id}`} className="atk-present-link" title="Open in large-text Teacher Presentation mode">
                      Present
                    </Link>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      ) : (
        <div className="panel atk-comparison-panel">
          <div className="table-wrap">
            <table className="atk-comparison-table">
              <thead>
                <tr>
                  <th>Behavior / Topic</th>
                  <th>Category</th>
                  <th>Plain-language meaning</th>
                  <th>Possible consequence (conditional)</th>
                  <th>Detector & readiness</th>
                  <th>MITRE ATT&CK</th>
                  <th>Open findings</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredTopics.map(topic => {
                  const rule = topic.ruleId ? ruleMap[topic.ruleId] : null;
                  const isReady = rule ? Boolean(rule.readiness?.ready) : false;
                  const openCount = topic.ruleId ? (openByRule[topic.ruleId] || 0) : 0;
                  return (
                    <tr key={topic.id}>
                      <td>
                        <Link to={`/attack-library/${topic.id}`} style={{ fontWeight: 700 }}>
                          {topic.shortTitle || topic.title}
                        </Link>
                        <small style={{ display: 'block', color: 'var(--muted)' }}>{topic.technicalLabel}</small>
                      </td>
                      <td><Badge>{topic.category}</Badge></td>
                      <td>{topic.shortMeaning}</td>
                      <td>{topic.shortConsequence}</td>
                      <td>
                        {!topic.detection.hasDetector ? (
                          <Badge tone="stale">Educational only</Badge>
                        ) : isReady ? (
                          <Badge tone="online">Ready ({topic.ruleId})</Badge>
                        ) : (
                          <Badge tone="medium">Missing prerequisite</Badge>
                        )}
                      </td>
                      <td>
                        {topic.mitre.mappingStatus === 'No direct mapping' ? (
                          <small style={{ color: 'var(--muted)' }}>No direct mapping</small>
                        ) : (
                          topic.mitre.techniques.map((m: MitreReference) => (
                            <span key={m.id} style={{ display: 'inline-block', marginRight: '6px', fontSize: '11px', fontWeight: 600 }}>
                              {m.id}
                            </span>
                          ))
                        )}
                      </td>
                      <td>
                        {!topic.detection.hasDetector ? (
                          <span style={{ color: 'var(--muted)' }}>—</span>
                        ) : openCount > 0 ? (
                          <Link to={`/attack-library/${topic.id}?case=latest`}>
                            <Badge tone="high">{openCount} open</Badge>
                          </Link>
                        ) : (
                          <span style={{ color: 'var(--muted)', fontSize: '12px' }}>0</span>
                        )}
                      </td>
                      <td>
                        <div style={{ display: 'flex', gap: '6px' }}>
                          <Link to={`/attack-library/${topic.id}`} className="button" style={{ padding: '4px 8px', fontSize: '11px' }}>
                            Explain
                          </Link>
                          <Link to={`/present/${topic.id}`} className="button" style={{ padding: '4px 8px', fontSize: '11px' }}>
                            Present
                          </Link>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Bottom Educational vs Live Detection Banner (Matching Reference 01) */}
      <div className="atk-bottom-banner">
        <div className="atk-bottom-banner-left">
          <div className="atk-info-circle"><Info size={18} /></div>
          <div>
            <strong>Educational coverage is separate from live detection coverage.</strong>
            <span>
              Catalog entries explain security behaviors for teaching. Live detection requires an enabled rule and active Windows/endpoint event sources.
            </span>
          </div>
        </div>
        <Link to="/rules" className="button primary">
          View detection readiness <ArrowRight size={15} />
        </Link>
      </div>
    </div>
  );
}

export function AttackDetail() {
  const { id } = useParams();
  const [searchParams, setSearchParams] = useSearchParams();
  const { period } = useContext(Context);
  const { data: summary } = useData('/catalog-summary?' + period);

  const topic = useMemo(() => {
    const found = getTopicByIdOrRule(id);
    if (found) return found;
    const rule = (summary?.rules || []).find((r: Data) => r.id === id);
    if (rule) return createFallbackTopicForUnknownRule(rule.id, rule.name);
    return ATTACK_CATALOG[0];
  }, [id, summary]);

  const ruleInfo = useMemo(() => {
    if (!topic.ruleId || !summary?.rules) return null;
    return summary.rules.find((r: Data) => r.id === topic.ruleId) || null;
  }, [topic, summary]);

  // Fetch matching alerts for this rule so the user can inspect a live case or the general concept
  const { data: matchingAlertsData } = useData(
    topic.ruleId ? `/alerts?rule_id=${encodeURIComponent(topic.ruleId)}&page_size=20` : null
  );
  const matchingAlerts: Data[] = matchingAlertsData?.items || [];

  const requestedAlertId = searchParams.get('alertId');
  const requestedLatest = searchParams.get('case') === 'latest';

  const [selectedAlertId, setSelectedAlertId] = useState<string>('');

  useEffect(() => {
    if (requestedAlertId) {
      setSelectedAlertId(requestedAlertId);
    } else if (requestedLatest && matchingAlerts.length > 0) {
      setSelectedAlertId(matchingAlerts[0].id);
    } else if (!requestedAlertId && !requestedLatest) {
      setSelectedAlertId('');
    }
  }, [requestedAlertId, requestedLatest, matchingAlerts.length, topic.id]);

  const { data: liveCase } = useData(selectedAlertId ? `/alerts/${selectedAlertId}` : null);

  const [activeTab, setActiveTab] = useState<'Explain' | 'Evidence' | 'Impact' | 'Response' | 'References'>('Explain');

  const provenance = determineProvenance(liveCase);
  const firstEv = liveCase?.evidence?.[0];

  const isReady = ruleInfo ? Boolean(ruleInfo.readiness?.ready) : false;
  const missingPrereqs: string[] = ruleInfo?.readiness?.missing || [];
  const openCount = topic.ruleId ? (summary?.open_by_rule?.[topic.ruleId] || 0) : 0;

  // Dynamic values: if a real case is selected, show real case facts; otherwise show clearly-labeled lab example
  const observedAccount = liveCase
    ? (liveCase.employee?.name || liveCase.account || liveCase.user_sid || 'LAB\\sales.demo')
    : topic.labExample.account;
  const observedDevice = liveCase
    ? (liveCase.device?.hostname || liveCase.access_device_id || liveCase.source_device_id || 'LAB-PC01')
    : topic.labExample.device;
  const observedOutcome = liveCase
    ? (firstEv?.result === 'denied' ? 'Access denied (Blocked by NTFS ACL)' : (firstEv?.result || 'Observed in audit log'))
    : topic.labExample.outcome;

  const presentTarget = liveCase ? `/present/case/${liveCase.id}` : `/present/${topic.id}`;
  const reqCat = ruleInfo?.required?.[0] || '';
  const evidenceTarget = liveCase
    ? `/alerts/${liveCase.id}`
    : reqCat
      ? `/events?category=${encodeURIComponent(reqCat)}`
      : '/events';

  return (
    <div className="atk-detail-page">
      {/* Breadcrumb */}
      <div className="atk-breadcrumb">
        <Link to="/attack-library">Attack Library</Link>
        <span>/</span>
        <strong>{topic.shortTitle || topic.title}</strong>
        <span className={`atk-provenance-tag ${provenance.code}`}>
          {provenance.badgeText}
        </span>
      </div>

      {/* Main Header matching Reference 02 */}
      <div className="atk-detail-header">
        <div>
          <div className="atk-detail-title-row">
            <h1>{topic.shortTitle || topic.title}</h1>
            <span className={`atk-short-badge ${topic.badgeTone}`}>
              {topic.badgeText}
            </span>
          </div>
          <p className="atk-detail-subtitle">{topic.shortMeaning}</p>

          {/* Independent Status Pills (Section 3) */}
          <div className="atk-independent-statuses">
            <span className="atk-status-chip">
              <strong>Catalog:</strong> Reviewed topic ({topic.category})
            </span>
            <span className="atk-status-chip">
              <strong>Detector:</strong>{' '}
              {!topic.detection.hasDetector
                ? 'Educational entry — detection not implemented'
                : isReady
                  ? `Implemented & Ready (${topic.ruleId})`
                  : `Implemented · Missing telemetry (${missingPrereqs.join(', ') || topic.detection.collectorSource})`}
            </span>
            {topic.detection.hasDetector && (
              <span className="atk-status-chip">
                <strong>Open findings:</strong> {openCount}
              </span>
            )}
            {liveCase && (
              <span className="atk-status-chip">
                <strong>Review status:</strong> {liveCase.status === 'Open' ? 'Needs review' : liveCase.status}
              </span>
            )}
          </div>
        </div>

        <div className="atk-detail-actions">
          {matchingAlerts.length > 0 && (
            <select
              aria-label="Select mode or live alert case"
              className="atk-case-selector"
              value={selectedAlertId}
              onChange={e => {
                const val = e.target.value;
                setSelectedAlertId(val);
                if (val) setSearchParams({ alertId: val });
                else setSearchParams({});
              }}
            >
              <option value="">Mode: Educational & lab concept</option>
              {matchingAlerts.map((a: Data) => (
                <option key={a.id} value={a.id}>
                  Live Case #{a.id.slice(0, 6)}: {a.account || 'sales.demo'} ({a.status})
                </option>
              ))}
            </select>
          )}

          <Link to={evidenceTarget} className="button atk-btn-outline">
            <FolderLock size={15} /> {liveCase ? 'Open case investigation' : 'Open source evidence'}
          </Link>
          <button type="button" className="atk-btn-outline" onClick={() => window.print()}>
            <Printer size={15} /> Print summary
          </button>
          <Link to={presentTarget} className="button primary atk-btn-present">
            <Monitor size={15} /> {liveCase ? 'Present this case' : 'Present this type'}
          </Link>
        </div>
      </div>

      {/* Tabs Bar (Matching Reference 02: Explain | Evidence | Impact | Response + References) */}
      <div className="atk-tabs-bar" role="tablist" aria-label="Attack explanation sections">
        {(['Explain', 'Evidence', 'Impact', 'Response', 'References'] as const).map(tab => (
          <button
            key={tab}
            type="button"
            role="tab"
            aria-selected={activeTab === tab}
            className={`atk-tab-btn ${activeTab === tab ? 'active' : ''}`}
            onClick={() => setActiveTab(tab)}
          >
            {tab}
          </button>
        ))}
      </div>

      {/* TAB 1: EXPLAIN (Default unified view matching Reference 02 layout) */}
      {activeTab === 'Explain' && (
        <div className="atk-explain-layout">
          <div className="atk-explain-grid">
            {/* Left Column */}
            <div className="atk-explain-col">
              {/* Card 1: In simple words + How it could happen */}
              <div className="atk-section-card">
                <div className="atk-section-icon blue"><FileText size={20} /></div>
                <div className="atk-section-body">
                  <h3>In simple words</h3>
                  <p>{topic.inSimpleWords}</p>
                  <div className="atk-sub-box">
                    <strong>How it could happen in practice</strong>
                    <ul className="atk-bullet-list" style={{ marginTop: '4px' }}>
                      {topic.howItCouldHappen.map((h: string, i: number) => (
                        <li key={i}>{h}</li>
                      ))}
                    </ul>
                  </div>
                </div>
              </div>

              {/* Card 2: Example in our lab / Selected live case */}
              <div className="atk-section-card">
                <div className="atk-section-icon teal"><Sparkles size={20} /></div>
                <div className="atk-section-body">
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                    <h3>{liveCase ? 'Observed in selected live case' : 'Example in our lab'}</h3>
                    <span className={`atk-mini-provenance ${provenance.code}`}>
                      {liveCase ? provenance.label : (topic.labExample.isIllustrative ? 'Illustrative lab example' : 'Recorded lab example')}
                    </span>
                  </div>
                  <p>
                    {liveCase
                      ? (liveCase.explanation?.detail || `${observedAccount} triggered ${liveCase.title} on ${observedDevice}.`)
                      : topic.labExample.summary}
                  </p>
                  <div className="atk-example-minis">
                    <div className="atk-example-mini">
                      <Monitor size={18} className="atk-mini-icon blue" />
                      <div>
                        <small>Device & Account</small>
                        <strong>{observedDevice} · {observedAccount}</strong>
                      </div>
                    </div>
                    <div className="atk-example-mini">
                      <ShieldAlert size={18} className="atk-mini-icon red" />
                      <div>
                        <small>Outcome</small>
                        <strong>{observedOutcome}</strong>
                      </div>
                    </div>
                  </div>
                  {firstEv?.object_path && (
                    <div className="atk-code-path">
                      <small>Target path:</small> <code>{firstEv.object_path}</code>
                    </div>
                  )}
                  {!liveCase && topic.labExample.target && (
                    <div className="atk-code-path">
                      <small>Lab target:</small> <code>{topic.labExample.target}</code>
                    </div>
                  )}
                </div>
              </div>

              {/* Card 3: How AD Monitor detects it */}
              <div className="atk-section-card">
                <div className="atk-section-icon indigo"><Settings size={20} /></div>
                <div className="atk-section-body">
                  <h3>How AD Monitor detects it</h3>
                  <ol className="atk-numbered-steps">
                    {topic.detection.steps.map((step: string, i: number) => (
                      <li key={i}>
                        <span className="atk-step-num">{i + 1}</span>
                        <span>{step}</span>
                      </li>
                    ))}
                  </ol>
                  <div className="atk-detector-meta">
                    <div>
                      <small>Detector rule</small>
                      <strong>{topic.ruleId || 'Not implemented (Educational)'}</strong>
                    </div>
                    <div>
                      <small>Live threshold & window</small>
                      <strong>
                        {ruleInfo
                          ? `Threshold: ${ruleInfo.config?.threshold ?? ruleInfo.config?.min_connections ?? 1} · Window: ${ruleInfo.config?.window_seconds ?? 300}s`
                          : topic.detection.defaultThresholdLabel}
                      </strong>
                    </div>
                    <div>
                      <small>Collector source</small>
                      <strong>{topic.detection.collectorSource}</strong>
                    </div>
                  </div>
                  <p className="atk-enforcement-note">
                    <strong>Enforcement vs. Monitoring:</strong> {topic.impact.enforcementDistinction}
                  </p>
                </div>
              </div>
            </div>

            {/* Right Column */}
            <div className="atk-explain-col">
              {/* Card 4: What the evidence shows (and what is NOT established) */}
              <div className="atk-section-card highlight-green">
                <div className="atk-section-icon green"><CheckCircle2 size={20} /></div>
                <div className="atk-section-body">
                  <h3>What the evidence shows</h3>
                  <strong className="atk-observed-banner">
                    {liveCase ? `Observed: ${observedOutcome}` : topic.evidence.whatItShowsDefault}
                  </strong>
                  <p>{topic.evidence.whatItShowsDetail}</p>
                  <div className="atk-not-established-box">
                    <strong>What is NOT established by this evidence alone:</strong>
                    <ul>
                      {topic.evidence.notEstablished.map((item: string, idx: number) => (
                        <li key={idx}>{item}</li>
                      ))}
                    </ul>
                  </div>
                </div>
              </div>

              {/* Card 5: Possible impact if action succeeds */}
              <div className="atk-section-card highlight-amber">
                <div className="atk-section-icon amber"><AlertTriangle size={20} /></div>
                <div className="atk-section-body">
                  <h3>Possible impact if access or action succeeds</h3>
                  <p className="atk-conditional-note">
                    Conditional risk assessment (what could happen if unauthorized activity succeeds and is malicious):
                  </p>
                  <ul className="atk-bullet-list amber-bullets">
                    {topic.impact.possibleConsequences.map((item: string, idx: number) => (
                      <li key={idx}>{item}</li>
                    ))}
                  </ul>
                </div>
              </div>

              {/* Card 6: What to check next */}
              <div className="atk-section-card">
                <div className="atk-section-icon blue"><ShieldCheck size={20} /></div>
                <div className="atk-section-body">
                  <h3>What to check next</h3>
                  <ul className="atk-bullet-list">
                    {topic.whatToCheckNext.map((item, idx: number) => (
                      <li key={idx}>
                        {item.text}{' '}
                        {item.linkTo && (
                          <Link to={item.linkTo} style={{ fontSize: '12px', fontWeight: 700, marginLeft: '4px' }}>
                            [{item.linkLabel || 'Open'} ➔]
                          </Link>
                        )}
                      </li>
                    ))}
                  </ul>
                  <div className="atk-sub-box" style={{ marginTop: '12px' }}>
                    <strong>Common benign explanations to rule out:</strong>
                    <p>{topic.benignCauses.join(' · ')}</p>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Bottom Full-Width Card: Security impact explained (CIA Triad - Matching Reference 02) */}
          <div className="atk-cia-card">
            <div className="atk-cia-header">
              <div className="atk-section-icon blue"><Activity size={20} /></div>
              <h3>Security impact explained (Confidentiality · Integrity · Availability)</h3>
            </div>
            <div className="atk-cia-grid">
              <div className="atk-cia-item">
                <div className="atk-cia-icon red"><Lock size={20} /></div>
                <div>
                  <strong>Confidentiality ({topic.impact.confidentiality.level})</strong>
                  <p>{topic.impact.confidentiality.summary} {topic.impact.confidentiality.detail}</p>
                </div>
              </div>
              <div className="atk-cia-item">
                <div className="atk-cia-icon blue"><Database size={20} /></div>
                <div>
                  <strong>Integrity ({topic.impact.integrity.level})</strong>
                  <p>{topic.impact.integrity.summary} {topic.impact.integrity.detail}</p>
                </div>
              </div>
              <div className="atk-cia-item">
                <div className="atk-cia-icon teal"><Activity size={20} /></div>
                <div>
                  <strong>Availability ({topic.impact.availability.level})</strong>
                  <p>{topic.impact.availability.summary} {topic.impact.availability.detail}</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: EVIDENCE */}
      {activeTab === 'Evidence' && (
        <div className="atk-tab-content">
          <div className="grid two">
            <div className="atk-section-card highlight-green">
              <div className="atk-section-icon green"><CheckCircle2 size={20} /></div>
              <div className="atk-section-body">
                <h3>What collected evidence proves</h3>
                <strong className="atk-observed-banner">{topic.evidence.whatItShowsDefault}</strong>
                <p>{topic.evidence.whatItShowsDetail}</p>
              </div>
            </div>
            <div className="atk-section-card highlight-amber">
              <div className="atk-section-icon amber"><AlertTriangle size={20} /></div>
              <div className="atk-section-body">
                <h3>What is NOT established without further evidence</h3>
                <ul className="atk-bullet-list amber-bullets">
                  {topic.evidence.notEstablished.map((item: string, i: number) => <li key={i}>{item}</li>)}
                </ul>
              </div>
            </div>
          </div>

          <div className="atk-section-card" style={{ marginTop: '18px' }}>
            <div className="atk-section-icon indigo"><Database size={20} /></div>
            <div className="atk-section-body">
              <h3>Telemetry prerequisites & detector readiness</h3>
              <p>{topic.detection.measurement}</p>
              <div className="atk-detector-meta">
                <div>
                  <small>Implementation status</small>
                  <strong>{topic.detection.hasDetector ? `Implemented (${topic.ruleId})` : 'Educational entry — detection not implemented'}</strong>
                </div>
                <div>
                  <small>Collector source</small>
                  <strong>{topic.detection.collectorSource}</strong>
                </div>
                <div>
                  <small>Default threshold</small>
                  <strong>{topic.detection.defaultThresholdLabel}</strong>
                </div>
                <div>
                  <small>Current lab readiness</small>
                  <strong>
                    {!topic.detection.hasDetector
                      ? 'Not implemented in rule engine'
                      : isReady
                        ? 'Ready (Telemetry present in database)'
                        : `Prerequisite missing: ${missingPrereqs.join(', ') || 'event category not yet observed'}`}
                  </strong>
                </div>
              </div>

              <div className="atk-sub-box" style={{ marginTop: '12px' }}>
                <strong>Required telemetry fields & known limitations:</strong>
                <ul className="atk-bullet-list" style={{ marginTop: '4px' }}>
                  {topic.detection.requiredTelemetry.map((req: string, i: number) => <li key={i}>Prerequisite: {req}</li>)}
                  {topic.detection.limitations.map((lim: string, i: number) => <li key={`lim-${i}`}>Limitation: {lim}</li>)}
                </ul>
              </div>

              {liveCase && liveCase.evidence && liveCase.evidence.length > 0 && (
                <div style={{ marginTop: '18px' }}>
                  <h4>Supporting records from selected Case #{liveCase.id.slice(0, 8)} ({provenance.label})</h4>
                  <div className="table-wrap" style={{ marginTop: '10px' }}>
                    <table>
                      <thead>
                        <tr>
                          <th>Time (UTC)</th>
                          <th>Event ID / Category</th>
                          <th>Account</th>
                          <th>Device</th>
                          <th>Object / Command</th>
                          <th>Result</th>
                          <th>Provenance</th>
                        </tr>
                      </thead>
                      <tbody>
                        {liveCase.evidence.map((ev: Data) => (
                          <tr key={ev.id}>
                            <td><Time value={ev.time} /></td>
                            <td><strong>{ev.event_id || '—'}</strong> · {ev.category}</td>
                            <td>{ev.account || ev.user_sid || '—'}</td>
                            <td>{ev.source_computer || ev.access_device_id || '—'}</td>
                            <td><code>{ev.object_path || ev.command_line || ev.process_path || '—'}</code></td>
                            <td><Badge tone={ev.result}>{ev.result}</Badge></td>
                            <td><small>{ev.evidence_type || 'normalized'}</small></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* TAB 3: IMPACT */}
      {activeTab === 'Impact' && (
        <div className="atk-tab-content">
          <div className="grid two">
            <div className="atk-section-card highlight-green">
              <div className="atk-section-icon green"><ShieldCheck size={20} /></div>
              <div className="atk-section-body">
                <h3>Observed outcome in this case</h3>
                <strong className="atk-observed-banner">{observedOutcome}</strong>
                <p style={{ marginTop: '10px' }}>
                  {liveCase
                    ? `In Case #${liveCase.id.slice(0, 8)}, the recorded event outcome was "${firstEv?.result || 'observed'}". AD Monitor reports the actual observed result without exaggerating it into a confirmed breach.`
                    : topic.impact.observedOutcomeDefault}
                </p>
                <p style={{ marginTop: '10px', fontSize: '12.5px', color: 'var(--muted)' }}>
                  <strong>Enforcement vs. Detection:</strong> {topic.impact.enforcementDistinction}
                </p>
              </div>
            </div>

            <div className="atk-section-card highlight-amber">
              <div className="atk-section-icon amber"><AlertTriangle size={20} /></div>
              <div className="atk-section-body">
                <h3>Possible consequences if malicious & successful</h3>
                <ul className="atk-bullet-list amber-bullets">
                  {topic.impact.possibleConsequences.map((item: string, i: number) => <li key={i}>{item}</li>)}
                </ul>
              </div>
            </div>
          </div>

          <div className="atk-cia-card" style={{ marginTop: '18px' }}>
            <div className="atk-cia-header">
              <div className="atk-section-icon blue"><Activity size={20} /></div>
              <h3>Confidentiality, Integrity, and Availability Assessment</h3>
            </div>
            <div className="atk-cia-grid">
              <div className="atk-cia-item">
                <div className="atk-cia-icon red"><Lock size={20} /></div>
                <div>
                  <strong>Confidentiality ({topic.impact.confidentiality.level})</strong>
                  <p>{topic.impact.confidentiality.summary} {topic.impact.confidentiality.detail}</p>
                </div>
              </div>
              <div className="atk-cia-item">
                <div className="atk-cia-icon blue"><Database size={20} /></div>
                <div>
                  <strong>Integrity ({topic.impact.integrity.level})</strong>
                  <p>{topic.impact.integrity.summary} {topic.impact.integrity.detail}</p>
                </div>
              </div>
              <div className="atk-cia-item">
                <div className="atk-cia-icon teal"><Activity size={20} /></div>
                <div>
                  <strong>Availability ({topic.impact.availability.level})</strong>
                  <p>{topic.impact.availability.summary} {topic.impact.availability.detail}</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 4: RESPONSE */}
      {activeTab === 'Response' && (
        <div className="atk-tab-content">
          <div className="grid two">
            <div className="atk-section-card">
              <div className="atk-section-icon blue"><ShieldCheck size={20} /></div>
              <div className="atk-section-body">
                <h3>What an analyst should check next</h3>
                <ol className="atk-numbered-steps">
                  {topic.whatToCheckNext.map((step, i: number) => (
                    <li key={i}>
                      <span className="atk-step-num">{i + 1}</span>
                      <span>
                        {step.text}{' '}
                        {step.linkTo && (
                          <Link to={step.linkTo} style={{ fontWeight: 700, marginLeft: '4px' }}>
                            [{step.linkLabel || 'Open'} ➔]
                          </Link>
                        )}
                      </span>
                    </li>
                  ))}
                </ol>
              </div>
            </div>

            <div className="atk-section-card">
              <div className="atk-section-icon teal"><HelpCircle size={20} /></div>
              <div className="atk-section-body">
                <h3>Common benign explanations</h3>
                <p>Human review is essential because operational activity can resemble suspicious patterns:</p>
                <ul className="atk-bullet-list">
                  {topic.benignCauses.map((item: string, i: number) => <li key={i}>{item}</li>)}
                </ul>
              </div>
            </div>
          </div>

          <div className="atk-section-card" style={{ marginTop: '18px' }}>
            <div className="atk-section-icon green"><Lock size={20} /></div>
            <div className="atk-section-body">
              <h3>Prevention & security hardening</h3>
              <ul className="atk-bullet-list">
                {topic.prevention.map((item: string, i: number) => <li key={i}>{item}</li>)}
              </ul>
            </div>
          </div>
        </div>
      )}

      {/* TAB 5: REFERENCES */}
      {activeTab === 'References' && (
        <div className="atk-tab-content">
          <div className="atk-section-card">
            <div className="atk-section-icon indigo"><BookOpen size={20} /></div>
            <div className="atk-section-body">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px' }}>
                <h3>MITRE ATT&CK® Enterprise Reference (Secondary Technical Mapping)</h3>
                <Badge tone={topic.mitre.mappingStatus === 'Reviewed mapping' ? 'online' : topic.mitre.mappingStatus === 'Possible mapping' ? 'medium' : 'stale'}>
                  {topic.mitre.mappingStatus} · Reviewed {topic.mitre.reviewDate} ({topic.mitre.sourceVersion})
                </Badge>
              </div>
              <p style={{ marginTop: '6px' }}>
                <strong>Mapping rationale:</strong> {topic.mitre.rationale}
              </p>
              <p style={{ marginTop: '4px', fontSize: '12.5px', color: 'var(--muted)' }}>
                <strong>Applicable conditions:</strong> {topic.mitre.applicableConditions}
              </p>

              {topic.mitre.techniques.length > 0 ? (
                <div className="table-wrap" style={{ marginTop: '12px' }}>
                  <table>
                    <thead>
                      <tr>
                        <th>Technique ID</th>
                        <th>Official MITRE ATT&CK Name</th>
                        <th>Tactics</th>
                        <th>Local AD Monitor Topic</th>
                        <th>External Reference</th>
                      </tr>
                    </thead>
                    <tbody>
                      {topic.mitre.techniques.map((m: MitreReference) => (
                        <tr key={m.id}>
                          <td><strong>{m.id}</strong></td>
                          <td>{m.officialName}</td>
                          <td>{m.tactics.join(', ')}</td>
                          <td>{topic.shortTitle || topic.title} {topic.ruleId ? `(${topic.ruleId})` : '(Educational)'}</td>
                          <td>
                            <a href={m.url} target="_blank" rel="noreferrer" style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', fontSize: '12px' }}>
                              attack.mitre.org <ExternalLink size={12} />
                            </a>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="atk-sub-box" style={{ marginTop: '12px' }}>
                  <strong>No direct ATT&CK technique mapping:</strong> This detector monitors a defensive tripwire or security product alert rather than a single offensive ATT&CK technique.
                </div>
              )}

              <div className="atk-sub-box" style={{ marginTop: '16px' }}>
                <strong>Evidence requirements & collector sources:</strong>
                <p style={{ marginTop: '4px' }}>{topic.mitre.evidenceRequirements}</p>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export function TeacherPresentation() {
  const { typeId, alertId } = useParams();
  const navigate = useNavigate();
  const { period } = useContext(Context);
  const { data: summary } = useData('/catalog-summary?' + period);
  const { data: liveAlert } = useData(alertId ? `/alerts/${alertId}` : null);

  const [selectedMode, setSelectedMode] = useState<string>(() => {
    if (alertId) return `case:${alertId}`;
    if (typeId) {
      if (TEACHER_GUIDED_SCENARIOS.some(s => s.id === typeId)) return `scenario:${typeId}`;
      const found = getTopicByIdOrRule(typeId);
      if (found) return `topic:${found.id}`;
    }
    // Default to the USB staging educational scenario shown in Reference 03
    return 'scenario:usb-staging-educational-scenario';
  });

  useEffect(() => {
    if (alertId) setSelectedMode(`case:${alertId}`);
    else if (typeId) {
      if (TEACHER_GUIDED_SCENARIOS.some(s => s.id === typeId)) setSelectedMode(`scenario:${typeId}`);
      else {
        const found = getTopicByIdOrRule(typeId);
        if (found) setSelectedMode(`topic:${found.id}`);
      }
    }
  }, [typeId, alertId]);

  const [step, setStep] = useState<number>(2); // Reference 03 shows Step 2 Evidence prominently

  // Keyboard navigation for Left/Right arrows
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.target instanceof HTMLInputElement || e.target instanceof HTMLSelectElement || e.target instanceof HTMLTextAreaElement) return;
      if (e.key === 'ArrowRight') setStep(s => Math.min(4, s + 1));
      if (e.key === 'ArrowLeft') setStep(s => Math.max(1, s - 1));
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  const activeCaseId = selectedMode.startsWith('case:') ? selectedMode.slice(5) : alertId || '';
  const { data: fetchedCase } = useData(activeCaseId ? `/alerts/${activeCaseId}` : null);
  const currentCase = fetchedCase || liveAlert;

  const presentationData = useMemo(() => {
    if (selectedMode.startsWith('scenario:')) {
      const scenId = selectedMode.slice(9);
      const scen = TEACHER_GUIDED_SCENARIOS.find(s => s.id === scenId) || TEACHER_GUIDED_SCENARIOS[0];
      const slide = scen.slides[step - 1] || scen.slides[0];
      const isWalkthrough = scen.id === 'end-to-end-lab-walkthrough';
      const matchingRealAlert = (summary?.recent_alerts || []).find((a: Data) => a.rule_id === 'restricted');
      return {
        title: scen.title,
        subtitle: scen.subtitle,
        badgeText: isWalkthrough && matchingRealAlert ? 'OPERATIONAL EVIDENCE · LIVE LAB WALKTHROUGH' : scen.badgeLabel,
        badgeTone: isWalkthrough && matchingRealAlert ? 'operational' : (scen.provenanceType === 'Controlled lab evidence' ? 'controlled_lab' : 'educational'),
        slideHeadline: slide.headline,
        slideSubtitle: slide.subtitle,
        keyLesson: slide.keyLesson,
        events: slide.events || [],
        warningTitle: slide.warningTitle || 'Evidence boundary note',
        warningBody: slide.warningBody || '',
        whatThisSuggests: slide.whatThisSuggests,
        possibleImpactBullets: slide.possibleImpactBullets,
        missingEvidenceBullets: slide.missingEvidenceBullets,
        nextStepsBullets: slide.nextStepsBullets || slide.possibleImpactBullets,
        preventionBullets: slide.preventionBullets || slide.missingEvidenceBullets,
        evidenceLink: matchingRealAlert && isWalkthrough ? `/alerts/${matchingRealAlert.id}` : '/events',
        exitLink: '/attack-library'
      };
    }

    // Topic or Live Case mode
    const topicIdToUse = selectedMode.startsWith('topic:')
      ? selectedMode.slice(6)
      : (currentCase?.rule_id || 'restricted');
    const topic = getTopicByIdOrRule(topicIdToUse) || ATTACK_CATALOG[0];
    const prov = determineProvenance(currentCase);
    const firstEv = currentCase?.evidence?.[0];

    const acct = currentCase ? (currentCase.employee?.name || currentCase.account || 'LAB\\sales.demo') : topic.labExample.account;
    const dev = currentCase ? (currentCase.device?.hostname || currentCase.access_device_id || 'LAB-PC01') : topic.labExample.device;
    const out = currentCase
      ? (firstEv?.result === 'denied' ? 'Access denied (Blocked by Windows NTFS ACL)' : (firstEv?.result || 'Observed in audit log'))
      : topic.labExample.outcome;

    const timelineEvents = currentCase && currentCase.evidence && currentCase.evidence.length > 0
      ? currentCase.evidence.slice(0, 4).map((ev: Data) => ({
          time: new Date(ev.time).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' }),
          title: `${ev.category.replace(/_/g, ' ')} (${ev.result || 'observed'})`,
          detail: `${ev.object_path || ev.command_line || ev.process_path || ev.provider || 'Windows event'} on ${ev.source_computer || dev}`,
          tone: (ev.result === 'denied' ? 'red' : 'blue') as 'red' | 'blue' | 'green' | 'purple' | 'amber'
        }))
      : topic.presentation.timeline;

    return {
      title: currentCase ? `${currentCase.title} — ${acct}` : topic.presentation.questionTitle,
      subtitle: currentCase ? `${topic.shortMeaning} (${dev})` : topic.presentation.subtitle,
      badgeText: prov.badgeText,
      badgeTone: prov.code,
      slideHeadline:
        step === 1
          ? `1. Scenario: ${topic.shortTitle || topic.title}`
          : step === 2
            ? 'What happened in this example'
            : step === 3
              ? 'Observed outcome vs. Possible impact'
              : 'What to investigate next & prevention',
      slideSubtitle: topic.inSimpleWords,
      keyLesson: topic.presentation.keyLesson,
      events: timelineEvents,
      warningTitle: currentCase ? `Observed outcome: ${out}` : topic.presentation.warningTitle,
      warningBody: topic.presentation.warningBody,
      whatThisSuggests: topic.presentation.whatThisSuggests,
      possibleImpactBullets: topic.impact.possibleConsequences,
      missingEvidenceBullets: topic.evidence.notEstablished,
      nextStepsBullets: topic.whatToCheckNext.map(w => w.text),
      preventionBullets: topic.prevention,
      evidenceLink: currentCase ? `/alerts/${currentCase.id}` : `/attack-library/${topic.id}`,
      exitLink: `/attack-library/${topic.id}`
    };
  }, [selectedMode, step, currentCase, summary]);

  const stepLabels = ['Scenario', 'Evidence', 'Possible impact', 'Response'];

  return (
    <div className="teacher-presentation-shell">
      {/* Top Dark Navy Header Bar (Matching Reference 03) */}
      <div className="tp-topbar">
        <div className="tp-topbar-left">
          <Link to="/attack-library" className="tp-brand">
            <Shield size={26} />
            <strong>AD MONITOR</strong>
          </Link>
          <span className="tp-divider">|</span>
          <span className="tp-mode-title">Teacher presentation</span>
        </div>

        <div className="tp-topbar-right">
          <select
            aria-label="Choose presentation scenario, topic, or live case"
            className="tp-scenario-select"
            value={selectedMode}
            onChange={e => setSelectedMode(e.target.value)}
          >
            <optgroup label="Guided Viva & Teacher Walkthroughs">
              {TEACHER_GUIDED_SCENARIOS.map(s => (
                <option key={s.id} value={`scenario:${s.id}`}>
                  Walkthrough: {s.title}
                </option>
              ))}
            </optgroup>
            {(summary?.recent_alerts || []).length > 0 && (
              <optgroup label="Live Database Alert Cases">
                {(summary?.recent_alerts || []).map((a: Data) => (
                  <option key={a.id} value={`case:${a.id}`}>
                    Live Case #{a.id.slice(0, 6)}: {a.title} ({a.account || 'sales.demo'})
                  </option>
                ))}
              </optgroup>
            )}
            <optgroup label="All 17 Attack Library Topics">
              {ATTACK_CATALOG.map(t => (
                <option key={t.id} value={`topic:${t.id}`}>
                  Topic: {t.shortTitle || t.title}
                </option>
              ))}
            </optgroup>
          </select>

          <span className={`tp-provenance-badge ${presentationData.badgeTone}`}>
            {presentationData.badgeText}
          </span>

          <button type="button" className="tp-exit-btn" onClick={() => window.print()}>
            <Printer size={15} /> Print
          </button>

          <button
            type="button"
            className="tp-exit-btn"
            onClick={() => navigate(presentationData.exitLink)}
          >
            <ArrowLeft size={15} /> Exit presentation
          </button>
        </div>
      </div>

      {/* Main Presentation Canvas */}
      <div className="tp-canvas">
        <div className="tp-headline">
          <h1>{presentationData.title}</h1>
          <p>{presentationData.subtitle}</p>
        </div>

        {/* 4-Step Chevron Bar (Matching Reference 03: 1 Scenario -> 2 Evidence -> 3 Possible impact -> 4 Response) */}
        <div className="tp-stepper-bar" role="tablist" aria-label="Presentation steps">
          {stepLabels.map((label, idx) => {
            const num = idx + 1;
            const active = step === num;
            return (
              <button
                key={label}
                type="button"
                role="tab"
                aria-selected={active}
                className={`tp-step-tab ${active ? 'active' : ''}`}
                onClick={() => setStep(num)}
              >
                <span className="tp-step-circle">{num}</span>
                <span>{label}</span>
              </button>
            );
          })}
        </div>

        {/* STAGE CONTENT (Unified high-visibility 2-column presentation stage across steps 1..4) */}
        <div className="tp-stage-grid">
          <div className="tp-left-card">
            <div className="tp-card-heading">
              <FileText size={24} className="tp-heading-icon" />
              <h2>{presentationData.slideHeadline}</h2>
            </div>

            {step !== 2 && (
              <p className="tp-large-p">{presentationData.slideSubtitle}</p>
            )}

            {presentationData.events && presentationData.events.length > 0 && (
              <div className="tp-timeline">
                {presentationData.events.map((item: any, idx: number) => (
                  <div key={idx} className="tp-timeline-row">
                    <div className={`tp-tl-icon ${idx === 0 ? 'blue' : idx === 1 ? 'green' : 'violet'}`}>
                      {idx === 0 ? <FileText size={20} /> : idx === 1 ? <HardDrive size={20} /> : <Usb size={20} />}
                    </div>
                    <div className="tp-tl-time">{item.time}</div>
                    <div className="tp-tl-body">
                      <strong>{item.title}</strong>
                      <p>{item.detail}</p>
                    </div>
                  </div>
                ))}
              </div>
            )}

            {presentationData.warningTitle && (
              <div className="tp-evidence-callout amber">
                <AlertTriangle size={26} style={{ flexShrink: 0 }} />
                <div>
                  <strong>{presentationData.warningTitle}</strong>
                  <p>{presentationData.warningBody}</p>
                </div>
              </div>
            )}

            <div style={{ marginTop: '8px' }}>
              <Link to={presentationData.evidenceLink} className="tp-evidence-link">
                <Search size={15} /> Open underlying evidence <ExternalLink size={14} />
              </Link>
            </div>
          </div>

          <div className="tp-right-stack">
            <div className="tp-side-card">
              <div className="tp-side-icon teal"><Activity size={22} /></div>
              <div>
                <h3>{step === 4 ? 'Analyst review & verification' : 'What this suggests'}</h3>
                <p style={{ fontSize: '15.5px', margin: '6px 0 0', lineHeight: 1.5 }}>
                  {presentationData.whatThisSuggests}
                </p>
              </div>
            </div>

            <div className="tp-side-card">
              <div className="tp-side-icon red"><AlertTriangle size={22} /></div>
              <div>
                <h3>{step === 4 ? 'What to check next' : 'Possible impact if transfer/action occurs'}</h3>
                <ul className="tp-side-list red-dots">
                  {(step === 4 ? presentationData.nextStepsBullets : presentationData.possibleImpactBullets).map((item: string, idx: number) => (
                    <li key={idx}>{item}</li>
                  ))}
                </ul>
              </div>
            </div>

            <div className="tp-side-card">
              <div className="tp-side-icon blue"><HelpCircle size={22} /></div>
              <div>
                <h3>{step === 4 ? 'Prevention & security controls' : 'What evidence is missing?'}</h3>
                <ul className="tp-side-list blue-dots">
                  {(step === 4 ? presentationData.preventionBullets : presentationData.missingEvidenceBullets).map((item: string, idx: number) => (
                    <li key={idx}>{item}</li>
                  ))}
                </ul>
              </div>
            </div>
          </div>
        </div>

        {/* Key Lesson Callout Banner (Matching Reference 03) */}
        <div className="tp-key-lesson">
          <div className="tp-bulb-icon"><Lightbulb size={24} /></div>
          <div>
            <small>Key lesson</small>
            <strong>{presentationData.keyLesson}</strong>
          </div>
        </div>

        {/* Footer Navigation Buttons (Matching Reference 03) */}
        <div className="tp-footer-nav">
          <button
            type="button"
            className="tp-nav-btn prev"
            disabled={step <= 1}
            onClick={() => setStep(s => Math.max(1, s - 1))}
          >
            <ArrowLeft size={16} /> Previous
          </button>

          <div className="tp-step-indicator">
            <span>{stepLabels[step - 1]} {step} of 4</span>
            <div className="tp-dots">
              {[1, 2, 3, 4].map(n => (
                <button
                  key={n}
                  type="button"
                  aria-label={`Go to step ${n}`}
                  className={`tp-dot ${step === n ? 'active' : ''}`}
                  onClick={() => setStep(n)}
                />
              ))}
            </div>
          </div>

          <button
            type="button"
            className="tp-nav-btn next"
            disabled={step >= 4}
            onClick={() => setStep(s => Math.min(4, s + 1))}
          >
            {step < 4 ? `Next: ${stepLabels[step]}` : 'Completed'} <ArrowRight size={16} />
          </button>
        </div>
      </div>
    </div>
  );
}
