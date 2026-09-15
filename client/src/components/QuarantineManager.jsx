import React, { useState, useEffect } from 'react';

export default function QuarantineManager({ currentUser, onReloadStats }) {
  const [quarantineList, setQuarantineList] = useState([]);
  const [loading, setLoading] = useState(false);
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [reviewNotes, setReviewNotes] = useState('');
  const [updating, setUpdating] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');

  const fetchQuarantine = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/v1/quarantine', {
        headers: {
          'x-user-role': currentUser.role,
          'x-user-clearance': currentUser.clearance
        }
      });
      const data = await res.json();
      if (data.success) {
        setQuarantineList(data.data || []);
      }
    } catch (err) {
      console.error('Failed to load quarantine:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchQuarantine();
  }, [currentUser]);

  const handleReview = async (id, status) => {
    setUpdating(true);
    setErrorMsg('');
    try {
      const res = await fetch(`/api/v1/quarantine/${id}/review`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          'x-user-role': currentUser.role,
          'x-user-clearance': currentUser.clearance,
          'x-user-email': currentUser.email,
          'x-user-id': currentUser.id
        },
        body: JSON.stringify({
          status,
          notes: reviewNotes || 'Analyst reviewed quarantine event'
        })
      });
      const data = await res.json();
      if (data.success) {
        setSelectedEvent(null);
        setReviewNotes('');
        fetchQuarantine();
        if (onReloadStats) onReloadStats();
      } else {
        setErrorMsg(data.error || 'Failed to update quarantine status');
      }
    } catch (err) {
      setErrorMsg(err.message || 'Network error');
    } finally {
      setUpdating(false);
    }
  };

  return (
    <div style={{ padding: '24px 0' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 20 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
            <span className="badge badge-clear">FR-2.4</span>
            <span className="badge badge-clear">§0 Constraint #3 (Zero Silent Data Loss)</span>
          </div>
          <h2 style={{ fontSize: 20, marginBottom: 4 }}>Quarantine Event Manager</h2>
          <p style={{ color: 'var(--text-secondary)', fontSize: 13 }}>
            Malformed, unsupported, or unparsed telemetry isolated to prevent data loss or silent pipeline drops.
          </p>
        </div>

        <button className="btn btn-secondary btn-sm" onClick={fetchQuarantine}>
          🔄 Refresh Quarantine
        </button>
      </div>

      {loading && (
        <div style={{ textAlign: 'center', padding: '50px 0', color: 'var(--text-secondary)' }}>
          Loading quarantined telemetry...
        </div>
      )}

      {!loading && quarantineList.length === 0 && (
        <div className="card" style={{ textAlign: 'center', padding: '60px 20px' }}>
          <div style={{ fontSize: 36, marginBottom: 12 }}>🛡️</div>
          <h3 style={{ marginBottom: 6 }}>Quarantine Queue Clean</h3>
          <p style={{ color: 'var(--text-secondary)', maxWidth: 500, margin: '0 auto', fontSize: 13 }}>
            Zero unparsed or malformed events in quarantine. Ingested events are validating and normalizing cleanly.
          </p>
        </div>
      )}

      {!loading && quarantineList.length > 0 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {quarantineList.map((item) => (
            <div 
              key={item._id}
              className="card"
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                borderLeft: `4px solid ${item.status === 'QUARANTINED' ? 'var(--color-amber)' : 'var(--color-emerald)'}`
              }}
            >
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--color-amber)', fontWeight: 600 }}>
                    {item._id}
                  </span>
                  <span style={{
                    fontSize: 10,
                    fontFamily: 'var(--font-mono)',
                    padding: '2px 6px',
                    borderRadius: 3,
                    background: item.status === 'QUARANTINED' ? 'rgba(245, 158, 11, 0.15)' : 'rgba(16, 185, 129, 0.15)',
                    color: item.status === 'QUARANTINED' ? 'var(--color-amber)' : 'var(--color-emerald)'
                  }}>
                    {item.status}
                  </span>
                  <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                    Source: <strong style={{ color: 'var(--text-primary)' }}>{item.sourceType}</strong>
                  </span>
                </div>

                <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-primary)', marginBottom: 4 }}>
                  {item.reason}
                </div>

                <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                  Quarantined: {new Date(item.quarantinedAt).toLocaleString()}
                  {item.resolvedBy && <span> • Reviewed by {item.resolvedBy}</span>}
                </div>
              </div>

              <div style={{ display: 'flex', gap: 8 }}>
                <button
                  className="btn btn-secondary btn-sm"
                  onClick={() => setSelectedEvent(item)}
                >
                  Inspect Payload
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Payload Inspection & Review Modal */}
      {selectedEvent && (
        <div className="modal-backdrop" onClick={() => setSelectedEvent(null)}>
          <div className="modal-content" style={{ maxWidth: 640 }} onClick={(e) => e.stopPropagation()}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 16 }}>
              <div>
                <span className="badge badge-amber">QUARANTINE RECORD</span>
                <h3 style={{ fontSize: 18, marginTop: 4 }}>Raw Payload &amp; Error Diagnostic</h3>
              </div>
              <button className="btn btn-secondary btn-sm" onClick={() => setSelectedEvent(null)}>✕</button>
            </div>

            <div style={{ marginBottom: 16 }}>
              <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 4 }}>REASON FOR QUARANTINE:</div>
              <div style={{ fontSize: 13, color: 'var(--color-amber)', background: 'rgba(245, 158, 11, 0.1)', padding: 8, borderRadius: 4 }}>
                {selectedEvent.reason}
              </div>
            </div>

            <div style={{ marginBottom: 16 }}>
              <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 4 }}>ORIGINAL RAW PAYLOAD:</div>
              <pre style={{
                background: '#040711',
                padding: 12,
                borderRadius: 4,
                border: '1px solid var(--border-subtle)',
                fontSize: 11,
                overflowX: 'auto',
                color: '#38bdf8',
                maxHeight: 200
              }}>
                {JSON.stringify(selectedEvent.rawPayload, null, 2)}
              </pre>
            </div>

            {/* Review actions */}
            <div style={{
              background: 'rgba(255, 255, 255, 0.02)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 4,
              padding: 12
            }}>
              <label style={{ display: 'block', fontSize: 12, color: 'var(--text-muted)', marginBottom: 4 }}>
                Analyst Review Notes (Audit Logged per §0 #1):
              </label>
              <textarea
                value={reviewNotes}
                onChange={(e) => setReviewNotes(e.target.value)}
                placeholder="e.g. Verified malformed syslog frame from legacy gateway. Parser rule created."
                rows={2}
                style={{
                  width: '100%',
                  background: 'var(--bg-secondary)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 4,
                  color: 'var(--text-primary)',
                  padding: 6,
                  fontSize: 12,
                  marginBottom: 10
                }}
              />

              {errorMsg && (
                <div style={{ color: 'var(--color-rose)', fontSize: 12, marginBottom: 8 }}>
                  ⚠️ {errorMsg}
                </div>
              )}

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
                <button
                  className="btn btn-secondary btn-sm"
                  onClick={() => handleReview(selectedEvent._id, 'IGNORED')}
                  disabled={updating}
                >
                  Mark Ignored
                </button>
                <button
                  className="btn btn-success btn-sm"
                  onClick={() => handleReview(selectedEvent._id, 'RESOLVED')}
                  disabled={updating}
                >
                  {updating ? 'Recording...' : '✓ Resolve Quarantine'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
