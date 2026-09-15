import React from 'react';

export default function ExplainabilityModal({ incident, onClose }) {
  if (!incident) return null;

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        {/* Modal Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 20 }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
              <span className="badge badge-clear">§0 Constraint #2</span>
              <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--color-cyan)', fontSize: 13 }}>
                {incident.incidentId}
              </span>
            </div>
            <h2 style={{ fontSize: 22 }}>Explainable Scoring Factor Breakdown</h2>
            <p style={{ color: 'var(--text-secondary)', fontSize: 13 }}>
              Full mathematical attribution and evidence reasons for {incident.title}
            </p>
          </div>
          <button 
            className="btn btn-secondary btn-sm"
            onClick={onClose}
            style={{ padding: '6px 10px' }}
          >
            ✕ Close
          </button>
        </div>

        {/* Priority Factors Section */}
        <div style={{ marginBottom: 28 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginBottom: 12 }}>
            <h3 style={{ fontSize: 16, color: 'var(--color-rose)' }}>
              1. Priority Score Attribution ({incident.priorityScore}/100)
            </h3>
            <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>Formula: &Sigma;(Score &times; Weight)</span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {incident.priorityFactors && incident.priorityFactors.map((f, idx) => (
              <div 
                key={idx}
                style={{
                  background: 'rgba(255, 255, 255, 0.03)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 'var(--radius-sm)',
                  padding: '12px 16px'
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                  <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{f.factor}</span>
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--color-amber)' }}>
                    Weight: {(f.weight * 100).toFixed(0)}% | Score: {f.score}/100
                  </span>
                </div>
                {/* Progress bar */}
                <div style={{ height: 6, background: '#1e293b', borderRadius: 3, overflow: 'hidden', marginBottom: 8 }}>
                  <div style={{
                    width: `${f.score}%`,
                    height: '100%',
                    background: f.score >= 80 ? 'var(--color-rose)' : f.score >= 60 ? 'var(--color-amber)' : 'var(--color-cyan)'
                  }} />
                </div>
                <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                  💬 <strong style={{ color: 'var(--text-muted)' }}>Reason:</strong> {f.reason}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Confidence Factors Section */}
        <div style={{ marginBottom: 28 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginBottom: 12 }}>
            <h3 style={{ fontSize: 16, color: 'var(--color-emerald)' }}>
              2. Confidence Score Attribution ({incident.confidenceScore}/100)
            </h3>
            <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>Cross-source telemetry corroboration</span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {incident.confidenceFactors && incident.confidenceFactors.map((f, idx) => (
              <div 
                key={idx}
                style={{
                  background: 'rgba(255, 255, 255, 0.03)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 'var(--radius-sm)',
                  padding: '12px 16px'
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                  <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{f.factor}</span>
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--color-emerald)' }}>
                    Weight: {(f.weight * 100).toFixed(0)}% | Score: {f.score}/100
                  </span>
                </div>
                <div style={{ height: 6, background: '#1e293b', borderRadius: 3, overflow: 'hidden', marginBottom: 8 }}>
                  <div style={{
                    width: `${f.score}%`,
                    height: '100%',
                    background: 'var(--color-emerald)'
                  }} />
                </div>
                <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                  💬 <strong style={{ color: 'var(--text-muted)' }}>Reason:</strong> {f.reason}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* ATT&CK Heuristic Attribution */}
        {incident.mitreAttack && incident.mitreAttack.length > 0 && (
          <div>
            <h3 style={{ fontSize: 16, color: 'var(--color-cyan)', marginBottom: 12 }}>
              3. MITRE ATT&CK Heuristic Mapping Factors (FR-5.2)
            </h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {incident.mitreAttack.map((m, mIdx) => (
                <div 
                  key={mIdx}
                  style={{
                    background: 'rgba(6, 182, 212, 0.05)',
                    border: '1px solid rgba(6, 182, 212, 0.2)',
                    borderRadius: 'var(--radius-sm)',
                    padding: '10px 14px'
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
                    <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--color-cyan)' }}>
                      {m.techniqueId} — {m.techniqueName}
                    </span>
                    <span className="badge badge-clear">{m.tactic}</span>
                  </div>
                  <ul style={{ paddingLeft: 18, fontSize: 12, color: 'var(--text-secondary)' }}>
                    {m.factors && m.factors.map((fact, fIdx) => (
                      <li key={fIdx}>{fact}</li>
                    ))}
                  </ul>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
