import React from 'react';

export default function TriageQueue({ 
  incidents, 
  userClearance, 
  onSelectIncident, 
  onExplainScore, 
  onOpenBluf,
  loading 
}) {
  return (
    <div style={{ padding: '24px 0' }}>
      {/* Triage Banner & TLP Filter Notice */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        marginBottom: 20
      }}>
        <div>
          <h2 style={{ fontSize: 20, marginBottom: 4 }}>Ranked Triage Queue (FR-6.2)</h2>
          <p style={{ color: 'var(--text-secondary)', fontSize: 13 }}>
            Alerts prioritized by transparent multi-factor risk, asset impact, and threat corroboration.
          </p>
        </div>
        <div style={{
          fontSize: 12,
          color: 'var(--text-muted)',
          background: 'rgba(255, 255, 255, 0.03)',
          padding: '6px 12px',
          borderRadius: 'var(--radius-sm)',
          border: '1px solid var(--border-subtle)',
          display: 'flex',
          alignItems: 'center',
          gap: 6
        }}>
          <span>🛡️ Query-Layer Clearance:</span>
          <span className={`badge badge-${userClearance.toLowerCase().replace('_', '-')}`}>
            TLP:{userClearance}
          </span>
          <span>(Redacted at API)</span>
        </div>
      </div>

      {loading && (
        <div style={{ textAlign: 'center', padding: '60px 0', color: 'var(--text-secondary)' }}>
          <div>🔄 Loading correlated triage queue...</div>
        </div>
      )}

      {!loading && incidents.length === 0 && (
        <div className="card" style={{ textAlign: 'center', padding: '60px 20px' }}>
          <div style={{ fontSize: 36, marginBottom: 12 }}>🛡️</div>
          <h3 style={{ marginBottom: 6 }}>No Incidents Accessible Under TLP:{userClearance}</h3>
          <p style={{ color: 'var(--text-secondary)', maxWidth: 500, margin: '0 auto', fontSize: 13 }}>
            All active threat alerts exceed your clearance level or no events have been ingested yet.
            Switch your analyst role in the header to simulate higher clearance (e.g. TLP:RED) or click "Ingest Telemetry".
          </p>
        </div>
      )}

      {!loading && incidents.length > 0 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          {incidents.map((incident, index) => {
            const priorityColor = incident.priorityScore >= 80 
              ? 'var(--color-rose)' 
              : incident.priorityScore >= 60 
                ? 'var(--color-amber)' 
                : 'var(--color-cyan)';

            return (
              <div 
                key={incident._id || incident.incidentId} 
                className="card"
                style={{
                  display: 'grid',
                  gridTemplateColumns: '120px 1fr 280px',
                  gap: 20,
                  alignItems: 'center',
                  borderLeft: `4px solid ${priorityColor}`
                }}
              >
                {/* Score Column */}
                <div style={{ textAlign: 'center' }}>
                  <div style={{
                    fontSize: 28,
                    fontWeight: 800,
                    fontFamily: 'var(--font-heading)',
                    color: priorityColor,
                    lineHeight: 1
                  }}>
                    {incident.priorityScore}
                  </div>
                  <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', marginTop: 4 }}>
                    Priority #{index + 1}
                  </div>
                  <div style={{
                    fontSize: 11,
                    fontFamily: 'var(--font-mono)',
                    color: 'var(--color-emerald)',
                    marginTop: 6,
                    background: 'rgba(16, 185, 129, 0.1)',
                    padding: '2px 6px',
                    borderRadius: 4
                  }}>
                    {incident.confidenceScore}% Conf
                  </div>
                </div>

                {/* Incident Information */}
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6, flexWrap: 'wrap' }}>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--color-cyan)', fontWeight: 600 }}>
                      {incident.incidentId}
                    </span>
                    <span className={`badge badge-${incident.severity.toLowerCase()}`}>
                      {incident.severity}
                    </span>
                    <span className={`badge badge-${incident.tlp.toLowerCase().replace('_', '-')}`}>
                      TLP:{incident.tlp}
                    </span>
                    <span style={{
                      fontSize: 11,
                      padding: '2px 6px',
                      borderRadius: 4,
                      background: incident.status === 'CLOSED' ? 'rgba(100, 116, 139, 0.2)' : 'rgba(6, 182, 212, 0.15)',
                      color: incident.status === 'CLOSED' ? 'var(--text-muted)' : 'var(--color-cyan)',
                      fontFamily: 'var(--font-mono)',
                      fontWeight: 600
                    }}>
                      {incident.status}
                    </span>
                    <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                      • {incident.eventCount || 0} correlated events
                    </span>
                  </div>

                  <h3 style={{ fontSize: 16, marginBottom: 6, color: 'var(--text-primary)' }}>
                    {incident.title}
                  </h3>

                  {/* MITRE ATT&CK Badges */}
                  <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginTop: 8 }}>
                    {incident.mitreAttack && incident.mitreAttack.map((m, mIdx) => (
                      <span 
                        key={mIdx}
                        style={{
                          fontSize: 11,
                          fontFamily: 'var(--font-mono)',
                          background: 'rgba(255, 255, 255, 0.05)',
                          color: 'var(--text-secondary)',
                          border: '1px solid var(--border-subtle)',
                          padding: '2px 6px',
                          borderRadius: 4
                        }}
                      >
                        {m.techniqueId}: {m.techniqueName}
                      </span>
                    ))}
                  </div>
                </div>

                {/* Interactive Action Triggers */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                  <button
                    className="btn btn-secondary btn-sm"
                    onClick={() => onExplainScore(incident)}
                    style={{ width: '100%', justifyContent: 'space-between' }}
                  >
                    <span>🔍 Factor Breakdown</span>
                    <span style={{ color: 'var(--color-cyan)' }}>§0 #2</span>
                  </button>

                  <button
                    className="btn btn-secondary btn-sm"
                    onClick={() => onSelectIncident(incident)}
                    style={{ width: '100%' }}
                  >
                    Investigate Evidence
                  </button>

                  <button
                    className="btn btn-primary btn-sm"
                    onClick={() => onOpenBluf(incident)}
                    style={{ width: '100%' }}
                  >
                    📄 Traceable BLUF
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
