import { useState } from 'react';
import { Link } from 'react-router-dom';
import { ShieldAlert, ExternalLink, X, ChevronRight, CheckCircle2, BookOpen } from 'lucide-react';
import { MITRE_TACTICS, getMitre } from './mitre';
import type { MitreTechnique } from './mitre';
import type { Data } from './core';

export function MitreMatrix({ alerts = [] }: { alerts?: Data[] }) {
  const [selectedTech, setSelectedTech] = useState<MitreTechnique | null>(null);
  const [filterActiveOnly, setFilterActiveOnly] = useState(false);

  // Group alerts by rule_id
  const alertsByRule: Record<string, Data[]> = {};
  for (const a of alerts) {
    const rid = a.rule_id || (a.explanation && a.explanation.rule_id);
    if (rid) {
      if (!alertsByRule[rid]) alertsByRule[rid] = [];
      alertsByRule[rid].push(a);
    }
  }

  const rulesWithFindingsCount = Object.keys(alertsByRule).length;

  return (
    <div className="mitre-matrix-container">
      <div className="mitre-matrix-header">
        <div>
          <div className="eyebrow" style={{ color: '#0284c7' }}>SECONDARY TECHNICAL REFERENCE · REVIEWED 2026-10-03</div>
          <h3 style={{ margin: '2px 0 6px', fontSize: '16px', display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
            MITRE ATT&CK® Reference & Detector Coverage
            <span className="mitre-coverage-tag">17 Catalog Topics · 14 Configured Rules</span>
            <span className="mitre-coverage-tag" style={{ background: rulesWithFindingsCount > 0 ? 'rgba(239, 68, 68, 0.14)' : undefined, color: rulesWithFindingsCount > 0 ? '#ef4444' : undefined }}>
              {rulesWithFindingsCount} Rules with Recent Findings
            </span>
          </h3>
          <p style={{ margin: 0, fontSize: '12px', color: 'var(--muted)' }}>
            Official MITRE ATT&CK® names are shown alongside AD Monitor&apos;s plain-language topics. Catalog presence is separate from live detector readiness and open findings.
          </p>
        </div>
        <div className="mitre-controls" style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
          <label style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11.5px', cursor: 'pointer' }}>
            <input
              type="checkbox"
              checked={filterActiveOnly}
              onChange={e => setFilterActiveOnly(e.target.checked)}
            />
            Show Only Rules with Recent Findings
          </label>
          <Link to="/attack-library" className="button" style={{ fontSize: '11.5px', padding: '5px 10px' }}>
            <BookOpen size={13} /> Open Attack Library
          </Link>
        </div>
      </div>

      <div className="mitre-columns-grid">
        {MITRE_TACTICS.map(tactic => {
          const matchingItems = tactic.items.filter(item => {
            if (!filterActiveOnly) return true;
            return item.ruleId && (alertsByRule[item.ruleId]?.length || 0) > 0;
          });

          if (matchingItems.length === 0 && filterActiveOnly) return null;

          return (
            <div key={tactic.id} className="mitre-column">
              <div className="mitre-column-title">
                <span className="mitre-tactic-id">{tactic.id}</span>
                <strong>{tactic.name}</strong>
              </div>
              <div className="mitre-techniques-list">
                {matchingItems.map(item => {
                  const ruleAlerts = item.ruleId ? alertsByRule[item.ruleId] || [] : [];
                  const hasFindings = ruleAlerts.length > 0;
                  const mitreInfo = getMitre(item.ruleId || item.topicId);

                  return (
                    <div
                      key={`${tactic.id}-${item.topicId}`}
                      className={`mitre-tech-card ${hasFindings ? 'triggered' : ''}`}
                      onClick={() => mitreInfo && setSelectedTech(mitreInfo)}
                    >
                      <div className="mitre-tech-header">
                        <span className="mitre-tech-id">{item.techId}</span>
                        {hasFindings ? (
                          <span className="mitre-pulse-badge">
                            <span className="mitre-radar-dot"></span>
                            {ruleAlerts.length} FINDING{ruleAlerts.length > 1 ? 'S' : ''}
                          </span>
                        ) : !item.implemented ? (
                          <span style={{ fontSize: '9.5px', color: 'var(--muted)', fontWeight: 600 }}>EDUCATIONAL</span>
                        ) : null}
                      </div>
                      <div className="mitre-tech-name" style={{ fontWeight: 700 }}>{item.localTitle}</div>
                      <div style={{ fontSize: '10.5px', color: 'var(--muted)', marginTop: '2px' }}>
                        ATT&CK: {item.officialName}
                      </div>
                      <div className="mitre-tech-footer" style={{ marginTop: '6px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <span style={{ fontSize: '10px', opacity: 0.85 }}>{item.mappingStatus}</span>
                        <ChevronRight size={12} />
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          );
        })}
      </div>

      {selectedTech && (
        <div className="mitre-modal-overlay" onClick={() => setSelectedTech(null)}>
          <div className="mitre-modal-content" onClick={e => e.stopPropagation()}>
            <div className="mitre-modal-header">
              <div>
                <span className="eyebrow" style={{ color: '#0284c7' }}>
                  {selectedTech.tactics.join(' · ').toUpperCase()} · {selectedTech.mappingStatus.toUpperCase()}
                </span>
                <h2>{selectedTech.localRuleTitle}</h2>
                <small style={{ color: 'var(--muted)', display: 'block', marginTop: '2px' }}>
                  Official ATT&CK Reference: <strong>{selectedTech.id} — {selectedTech.officialName}</strong>
                </small>
              </div>
              <button className="icon-button" onClick={() => setSelectedTech(null)}>
                <X size={18} />
              </button>
            </div>

            <div className="mitre-modal-body">
              <div className="mitre-section">
                <h4>Plain-Language Explanation & Mapping Rationale</h4>
                <p>{selectedTech.description}</p>
                <p style={{ fontSize: '12px', color: 'var(--muted)', marginTop: '6px' }}>
                  <strong>Rationale ({selectedTech.reviewedDate}):</strong> {selectedTech.rationale}
                </p>
              </div>

              <div className="mitre-section">
                <h4>Related Findings in Current Period</h4>
                {selectedTech.ruleId && (alertsByRule[selectedTech.ruleId]?.length || 0) > 0 ? (
                  <div className="mitre-active-alerts">
                    {alertsByRule[selectedTech.ruleId].map(a => (
                      <div key={a.id} className="mitre-alert-item">
                        <ShieldAlert size={16} className="text-red" />
                        <div style={{ flex: 1 }}>
                          <strong>{a.title}</strong>
                          <small style={{ display: 'block', color: 'var(--muted)' }}>
                            Account: {a.account || a.user_sid || 'Unknown identity'} · Status: {a.status}
                          </small>
                        </div>
                        <Link to={`/alerts/${a.id}`} className="button" style={{ padding: '4px 8px', fontSize: '11px' }}>
                          Investigate Case <ExternalLink size={12} />
                        </Link>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p style={{ color: 'var(--muted)', fontSize: '12px' }}>
                    No recent findings for this topic in the selected period. Remember: no findings does not automatically prove absence of activity if telemetry prerequisites are disabled.
                  </p>
                )}
              </div>

              <div className="mitre-section">
                <h4>What to Check Next</h4>
                <div className="mitre-remediation-checklist">
                  {selectedTech.remediation.map((step, idx) => (
                    <div key={idx} className="remediation-item">
                      <CheckCircle2 size={15} style={{ color: '#10b981', flexShrink: 0, marginTop: '2px' }} />
                      <span>{step}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            <div className="mitre-modal-footer">
              <Link
                to={`/attack-library/${selectedTech.topicId}`}
                className="button primary"
                style={{ fontSize: '11.5px' }}
                onClick={() => setSelectedTech(null)}
              >
                <BookOpen size={14} /> Open Full Explanation & Impact
              </Link>
              {selectedTech.id.startsWith('T') && (
                <a
                  href={`https://attack.mitre.org/techniques/${selectedTech.id.split(' ')[0].replace('.', '/')}/`}
                  target="_blank"
                  rel="noreferrer"
                  className="button"
                  style={{ fontSize: '11.5px' }}
                >
                  Official MITRE ATT&CK Page ↗
                </a>
              )}
              <button onClick={() => setSelectedTech(null)} style={{ fontSize: '11.5px' }}>
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
