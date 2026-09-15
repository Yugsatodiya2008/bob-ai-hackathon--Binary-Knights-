import React, { useState } from 'react';

export default function IncidentDetailModal({ 
  incident, 
  onClose, 
  currentUser, 
  onStatusUpdate, 
  onOpenBluf 
}) {
  const [newStatus, setNewStatus] = useState(incident?.status || 'OPEN');
  const [analystName, setAnalystName] = useState(currentUser?.email || 'Sarah Vance');
  const [rationale, setRationale] = useState('');
  const [signOffConfirmed, setSignOffConfirmed] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState('');

  if (!incident) return null;

  const handleSaveStatus = async (e) => {
    e.preventDefault();
    setErrorMessage('');

    if (newStatus === 'CLOSED') {
      if (!signOffConfirmed) {
        setErrorMessage('§0 Constraint #1: Explicit analyst sign-off confirmation is required to close an incident.');
        return;
      }
      if (!rationale.trim()) {
        setErrorMessage('§0 Constraint #1: A non-empty remediation/containment rationale is mandatory.');
        return;
      }
    }

    setSubmitting(true);
    try {
      await onStatusUpdate(incident._id || incident.incidentId, {
        status: newStatus,
        analystName,
        rationale: rationale.trim(),
        signOffConfirmed
      });
      onClose();
    } catch (err) {
      setErrorMessage(err.message || 'Failed to update status');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal-content" style={{ maxWidth: 880 }} onClick={(e) => e.stopPropagation()}>
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 20 }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
              <span className={`badge badge-${incident.severity.toLowerCase()}`}>
                {incident.severity}
              </span>
              <span className={`badge badge-${incident.tlp.toLowerCase().replace('_', '-')}`}>
                TLP:{incident.tlp}
              </span>
              <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--color-cyan)', fontSize: 13 }}>
                {incident.incidentId}
              </span>
            </div>
            <h2 style={{ fontSize: 22 }}>{incident.title}</h2>
            <p style={{ color: 'var(--text-secondary)', fontSize: 13 }}>
              Correlated Multi-Source Telemetry &amp; Evidence Dossier
            </p>
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button className="btn btn-primary btn-sm" onClick={() => onOpenBluf(incident)}>
              📄 View BLUF
            </button>
            <button className="btn btn-secondary btn-sm" onClick={onClose}>
              ✕ Close
            </button>
          </div>
        </div>

        {/* Scores & Summary strip */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(4, 1fr)',
          gap: 12,
          marginBottom: 24,
          background: 'rgba(255, 255, 255, 0.02)',
          padding: 14,
          borderRadius: 'var(--radius-sm)',
          border: '1px solid var(--border-subtle)'
        }}>
          <div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>PRIORITY SCORE</div>
            <div style={{ fontSize: 20, fontWeight: 700, color: 'var(--color-rose)', fontFamily: 'var(--font-heading)' }}>
              {incident.priorityScore}/100
            </div>
          </div>
          <div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>CONFIDENCE SCORE</div>
            <div style={{ fontSize: 20, fontWeight: 700, color: 'var(--color-emerald)', fontFamily: 'var(--font-heading)' }}>
              {incident.confidenceScore}%
            </div>
          </div>
          <div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>CORRELATED EVENTS</div>
            <div style={{ fontSize: 20, fontWeight: 700, color: 'var(--color-cyan)', fontFamily: 'var(--font-heading)' }}>
              {incident.eventRefs ? incident.eventRefs.length : incident.eventCount || 0}
            </div>
          </div>
          <div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>CURRENT STATUS</div>
            <div style={{ fontSize: 16, fontWeight: 600, color: 'var(--text-primary)', textTransform: 'uppercase', marginTop: 4 }}>
              {incident.status}
            </div>
          </div>
        </div>

        {/* Correlated Evidence Table */}
        <div style={{ marginBottom: 24 }}>
          <h3 style={{ fontSize: 16, marginBottom: 12, display: 'flex', alignItems: 'center', gap: 8 }}>
            <span>Telemetry Evidence Trail ({incident.eventRefs ? incident.eventRefs.length : 0})</span>
            <span style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 400 }}>ECS Aligned</span>
          </h3>

          {incident.eventRefs && incident.eventRefs.length > 0 ? (
            <div style={{
              maxHeight: 240,
              overflowY: 'auto',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-sm)',
              background: 'rgba(0, 0, 0, 0.2)'
            }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: 12 }}>
                <thead>
                  <tr style={{ background: 'rgba(255, 255, 255, 0.04)', color: 'var(--text-secondary)' }}>
                    <th style={{ padding: '8px 12px' }}>Event ID</th>
                    <th style={{ padding: '8px 12px' }}>Source</th>
                    <th style={{ padding: '8px 12px' }}>Type</th>
                    <th style={{ padding: '8px 12px' }}>Source &rarr; Dest IP</th>
                    <th style={{ padding: '8px 12px' }}>Process / User</th>
                  </tr>
                </thead>
                <tbody>
                  {incident.eventRefs.map((ev, idx) => (
                    <tr key={ev._id || idx} style={{ borderTop: '1px solid var(--border-subtle)' }}>
                      <td style={{ padding: '8px 12px', fontFamily: 'var(--font-mono)', color: 'var(--color-cyan)' }}>
                        {ev.eventId || ev._id?.slice(-8)}
                      </td>
                      <td style={{ padding: '8px 12px', textTransform: 'capitalize' }}>
                        {ev.source}
                      </td>
                      <td style={{ padding: '8px 12px', color: 'var(--text-secondary)' }}>
                        {ev.eventType}
                      </td>
                      <td style={{ padding: '8px 12px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                        {ev.sourceIp || '—'} &rarr; {ev.destinationIp || '—'}
                      </td>
                      <td style={{ padding: '8px 12px', fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>
                        {ev.processName || ev.user || '—'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>
              No correlated event refs populated on this record.
            </div>
          )}
        </div>

        {/* Human-in-the-Loop Incident Status Management (§0 Constraint #1) */}
        <div style={{
          background: 'rgba(6, 182, 212, 0.04)',
          border: '1px solid rgba(6, 182, 212, 0.25)',
          borderRadius: 'var(--radius-sm)',
          padding: 18
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
            <span className="badge badge-clear">§0 Constraint #1</span>
            <h4 style={{ fontSize: 15, color: 'var(--text-primary)' }}>
              Human-in-the-Loop Status Transition &amp; Closure
            </h4>
          </div>
          <p style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 14 }}>
            Autonomous closure is strictly blocked by architectural constraint. Incident closure mandates analyst sign-off and logged rationale.
          </p>

          <form onSubmit={handleSaveStatus} style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
              <div>
                <label style={{ display: 'block', fontSize: 12, color: 'var(--text-muted)', marginBottom: 4 }}>
                  Transition Status:
                </label>
                <select
                  value={newStatus}
                  onChange={(e) => setNewStatus(e.target.value)}
                  style={{
                    width: '100%',
                    background: 'var(--bg-secondary)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: 4,
                    color: 'var(--text-primary)',
                    padding: '8px 10px',
                    fontSize: 13
                  }}
                >
                  <option value="OPEN">OPEN (Unassigned)</option>
                  <option value="IN_TRIAGE">IN_TRIAGE (Active Investigation)</option>
                  <option value="ESCALATED">ESCALATED (Tier 3 / CSIRT)</option>
                  <option value="CLOSED">CLOSED (Requires Sign-Off)</option>
                </select>
              </div>

              <div>
                <label style={{ display: 'block', fontSize: 12, color: 'var(--text-muted)', marginBottom: 4 }}>
                  Analyst Sign-Off Name:
                </label>
                <input
                  type="text"
                  value={analystName}
                  onChange={(e) => setAnalystName(e.target.value)}
                  required
                  placeholder="e.g. Lead Analyst Sarah Vance"
                  style={{
                    width: '100%',
                    background: 'var(--bg-secondary)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: 4,
                    color: 'var(--text-primary)',
                    padding: '8px 10px',
                    fontSize: 13
                  }}
                />
              </div>
            </div>

            {newStatus === 'CLOSED' && (
              <div style={{
                background: 'rgba(239, 68, 68, 0.08)',
                border: '1px solid rgba(239, 68, 68, 0.3)',
                borderRadius: 4,
                padding: 12,
                display: 'flex',
                flexDirection: 'column',
                gap: 10
              }}>
                <div>
                  <label style={{ display: 'block', fontSize: 12, color: 'var(--color-rose)', fontWeight: 600, marginBottom: 4 }}>
                    Mandatory Closure Rationale:
                  </label>
                  <textarea
                    value={rationale}
                    onChange={(e) => setRationale(e.target.value)}
                    placeholder="Describe eradication steps, host containment verification, and root cause findings..."
                    rows={3}
                    required
                    style={{
                      width: '100%',
                      background: 'var(--bg-secondary)',
                      border: '1px solid var(--border-subtle)',
                      borderRadius: 4,
                      color: 'var(--text-primary)',
                      padding: 8,
                      fontSize: 12,
                      fontFamily: 'var(--font-sans)',
                      resize: 'vertical'
                    }}
                  />
                </div>

                <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer', fontSize: 12, color: 'var(--text-primary)' }}>
                  <input
                    type="checkbox"
                    checked={signOffConfirmed}
                    onChange={(e) => setSignOffConfirmed(e.target.checked)}
                  />
                  <span>
                    I confirm that host containment has been verified and this incident is resolved. (Audit logged per FR-11.1)
                  </span>
                </label>
              </div>
            )}

            {errorMessage && (
              <div style={{ color: 'var(--color-rose)', fontSize: 12 }}>
                ⚠️ {errorMessage}
              </div>
            )}

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
              <button type="button" className="btn btn-secondary btn-sm" onClick={onClose}>
                Cancel
              </button>
              <button 
                type="submit" 
                className={`btn btn-sm ${newStatus === 'CLOSED' ? 'btn-danger' : 'btn-primary'}`}
                disabled={submitting}
              >
                {submitting ? 'Recording Audit...' : `Commit Status &rarr; ${newStatus}`}
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
}
