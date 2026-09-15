import React, { useState, useEffect } from 'react';

export default function MitreHeatmap({ heatmapData, onSelectTechnique }) {
  const [tactics, setTactics] = useState([]);
  const [selectedTech, setSelectedTech] = useState(null);

  useEffect(() => {
    if (heatmapData && heatmapData.tactics) {
      setTactics(heatmapData.tactics);
    }
  }, [heatmapData]);

  return (
    <div style={{ padding: '24px 0' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 20 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
            <span className="badge badge-clear">FR-5.3</span>
            <span className="badge badge-clear">§0 Constraint #6 (100% Air-Gapped)</span>
          </div>
          <h2 style={{ fontSize: 20, marginBottom: 4 }}>MITRE ATT&CK&reg; Enterprise Heatmap Matrix</h2>
          <p style={{ color: 'var(--text-secondary)', fontSize: 13 }}>
            Offline mirror of ATT&CK v14.1 tactics and techniques mapped against active incident telemetry.
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 14, fontSize: 12, color: 'var(--text-muted)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <span style={{ width: 12, height: 12, borderRadius: 2, background: 'rgba(239, 68, 68, 0.4)', border: '1px solid #ef4444' }} />
            <span>High Activity (3+ hits)</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <span style={{ width: 12, height: 12, borderRadius: 2, background: 'rgba(245, 158, 11, 0.3)', border: '1px solid #f59e0b' }} />
            <span>Moderate (1-2 hits)</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <span style={{ width: 12, height: 12, borderRadius: 2, background: 'rgba(255, 255, 255, 0.03)', border: '1px solid var(--border-subtle)' }} />
            <span>Monitored Baseline</span>
          </div>
        </div>
      </div>

      {/* Heatmap Matrix Grid */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
        gap: 12,
        alignItems: 'start',
        overflowX: 'auto',
        paddingBottom: 20
      }}>
        {tactics.map((tactic) => (
          <div 
            key={tactic.id}
            className="card"
            style={{
              padding: 12,
              display: 'flex',
              flexDirection: 'column',
              gap: 8,
              minWidth: 190
            }}
          >
            {/* Tactic Column Header */}
            <div style={{
              borderBottom: '1px solid var(--border-subtle)',
              paddingBottom: 8,
              marginBottom: 4
            }}>
              <div style={{ fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--color-cyan)' }}>
                {tactic.id}
              </div>
              <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)' }}>
                {tactic.name}
              </div>
            </div>

            {/* Techniques under tactic */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {tactic.techniques && tactic.techniques.map((tech) => {
                const hits = tech.hitCount || 0;
                const isHigh = hits >= 3;
                const isMed = hits > 0 && hits < 3;

                const bg = isHigh 
                  ? 'rgba(239, 68, 68, 0.25)' 
                  : isMed 
                    ? 'rgba(245, 158, 11, 0.2)' 
                    : 'rgba(255, 255, 255, 0.02)';

                const borderColor = isHigh 
                  ? '#ef4444' 
                  : isMed 
                    ? '#f59e0b' 
                    : 'var(--border-subtle)';

                return (
                  <div
                    key={tech.id}
                    onClick={() => setSelectedTech(tech)}
                    style={{
                      background: bg,
                      border: `1px solid ${borderColor}`,
                      borderRadius: 4,
                      padding: '6px 8px',
                      cursor: 'pointer',
                      transition: 'all 0.15s ease'
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: isHigh ? '#fca5a5' : isMed ? '#fde047' : 'var(--text-muted)' }}>
                        {tech.id}
                      </span>
                      {hits > 0 && (
                        <span style={{
                          fontSize: 10,
                          fontFamily: 'var(--font-mono)',
                          fontWeight: 700,
                          background: isHigh ? 'var(--color-rose)' : 'var(--color-amber)',
                          color: '#000',
                          padding: '1px 5px',
                          borderRadius: 3
                        }}>
                          {hits} {hits === 1 ? 'hit' : 'hits'}
                        </span>
                      )}
                    </div>
                    <div style={{ fontSize: 11, color: 'var(--text-primary)', marginTop: 2, lineHeight: 1.2 }}>
                      {tech.name}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        ))}
      </div>

      {/* Selected Technique Detail Drawer / Modal */}
      {selectedTech && (
        <div className="modal-backdrop" onClick={() => setSelectedTech(null)}>
          <div className="modal-content" style={{ maxWidth: 540 }} onClick={(e) => e.stopPropagation()}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 16 }}>
              <div>
                <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--color-cyan)', fontSize: 13 }}>
                  {selectedTech.id}
                </span>
                <h3 style={{ fontSize: 18, marginTop: 2 }}>{selectedTech.name}</h3>
              </div>
              <button className="btn btn-secondary btn-sm" onClick={() => setSelectedTech(null)}>✕</button>
            </div>

            <div style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.6, marginBottom: 16 }}>
              {selectedTech.description || 'Monitored Enterprise ATT&CK matrix technique.'}
            </div>

            <div style={{
              background: 'rgba(255, 255, 255, 0.03)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 4,
              padding: 12,
              fontSize: 12
            }}>
              <div style={{ color: 'var(--text-muted)' }}>TELEMETRY DETECTIONS:</div>
              <div style={{ fontSize: 18, fontWeight: 700, color: selectedTech.hitCount > 0 ? 'var(--color-rose)' : 'var(--text-secondary)', marginTop: 2 }}>
                {selectedTech.hitCount || 0} Incident Corroborations
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
