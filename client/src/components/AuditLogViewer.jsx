import React, { useState, useEffect } from 'react';

export default function AuditLogViewer({ currentUser }) {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');

  const fetchLogs = async () => {
    setLoading(true);
    setErrorMsg('');
    try {
      const res = await fetch('/api/v1/audit-logs', {
        headers: {
          'x-user-role': currentUser.role,
          'x-user-clearance': currentUser.clearance,
          'x-user-email': currentUser.email
        }
      });
      const data = await res.json();
      if (data.success) {
        setLogs(data.data || []);
      } else {
        setErrorMsg(data.error || 'Failed to fetch audit logs');
      }
    } catch (err) {
      setErrorMsg(err.message || 'Network error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
  }, [currentUser]);

  const isRestricted = currentUser.role !== 'ADMIN' && currentUser.role !== 'COMMANDER';

  return (
    <div style={{ padding: '24px 0' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 20 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
            <span className="badge badge-clear">FR-11.2</span>
            <span className="badge badge-clear">§0 Constraint #1 &amp; #4</span>
          </div>
          <h2 style={{ fontSize: 20, marginBottom: 4 }}>Immutable Security Audit Trail</h2>
          <p style={{ color: 'var(--text-secondary)', fontSize: 13 }}>
            Tamper-proof chronological record of operator actions, status transitions, and clearance queries.
          </p>
        </div>

        <button className="btn btn-secondary btn-sm" onClick={fetchLogs}>
          🔄 Refresh Audit Logs
        </button>
      </div>

      {isRestricted ? (
        <div className="card" style={{ textAlign: 'center', padding: '60px 20px', borderLeft: '4px solid var(--color-rose)' }}>
          <div style={{ fontSize: 36, marginBottom: 12 }}>🔒</div>
          <h3 style={{ color: 'var(--color-rose)', marginBottom: 6 }}>Access Denied: RBAC Restricted (FR-11.2)</h3>
          <p style={{ color: 'var(--text-secondary)', maxWidth: 500, margin: '0 auto', fontSize: 13 }}>
            Audit log inspection requires <strong>COMMANDER</strong> or <strong>ADMIN</strong> privileges. Your current role is <strong>{currentUser.role}</strong>.
            Switch your analyst persona in the top header to Commander or Admin to unlock this view.
          </p>
        </div>
      ) : loading ? (
        <div style={{ textAlign: 'center', padding: '50px 0', color: 'var(--text-secondary)' }}>
          Fetching immutable audit records...
        </div>
      ) : errorMsg ? (
        <div className="card" style={{ color: 'var(--color-rose)' }}>
          ⚠️ {errorMsg}
        </div>
      ) : logs.length === 0 ? (
        <div className="card" style={{ textAlign: 'center', padding: '60px 20px' }}>
          <h3>No audit logs recorded yet.</h3>
        </div>
      ) : (
        <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: 12 }}>
              <thead>
                <tr style={{ background: 'rgba(255, 255, 255, 0.04)', color: 'var(--text-secondary)' }}>
                  <th style={{ padding: '12px 16px' }}>Timestamp</th>
                  <th style={{ padding: '12px 16px' }}>Actor / Role</th>
                  <th style={{ padding: '12px 16px' }}>Action</th>
                  <th style={{ padding: '12px 16px' }}>Resource</th>
                  <th style={{ padding: '12px 16px' }}>Details / Rationale</th>
                </tr>
              </thead>
              <tbody>
                {logs.map((log) => (
                  <tr key={log._id} style={{ borderTop: '1px solid var(--border-subtle)' }}>
                    <td style={{ padding: '12px 16px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                      {new Date(log.timestamp).toLocaleTimeString()} {new Date(log.timestamp).toLocaleDateString()}
                    </td>
                    <td style={{ padding: '12px 16px' }}>
                      <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                        {log.userEmail || log.userId}
                      </div>
                      <span className="badge badge-clear" style={{ fontSize: 9 }}>
                        {log.role}
                      </span>
                    </td>
                    <td style={{ padding: '12px 16px' }}>
                      <span style={{
                        fontFamily: 'var(--font-mono)',
                        fontSize: 11,
                        color: log.action.includes('CLOSED') ? 'var(--color-rose)' : log.action.includes('APPROVED') ? 'var(--color-emerald)' : 'var(--color-cyan)',
                        fontWeight: 600
                      }}>
                        {log.action}
                      </span>
                    </td>
                    <td style={{ padding: '12px 16px', fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>
                      {log.resourceType}: {log.resourceId}
                    </td>
                    <td style={{ padding: '12px 16px', maxWidth: 300, color: 'var(--text-secondary)' }}>
                      {log.details?.rationale || log.details?.notes || JSON.stringify(log.details)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
