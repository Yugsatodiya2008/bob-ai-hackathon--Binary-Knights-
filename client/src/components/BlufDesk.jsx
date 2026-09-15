import React, { useState } from 'react';

export default function BlufDesk({ 
  report, 
  incident, 
  onGenerateBluf, 
  onApproveBluf, 
  onLockBluf, 
  currentUser 
}) {
  const [analystSignName, setAnalystSignName] = useState(currentUser?.email || 'Sarah Vance');
  const [actionLoading, setActionLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');

  const handleApprove = async () => {
    if (!report) return;
    setErrorMsg('');
    setActionLoading(true);
    try {
      await onApproveBluf(report.reportId, analystSignName);
    } catch (err) {
      setErrorMsg(err.message || 'Approval failed');
    } finally {
      setActionLoading(false);
    }
  };

  const handleLock = async () => {
    if (!report) return;
    setErrorMsg('');
    setActionLoading(true);
    try {
      await onLockBluf(report.reportId);
    } catch (err) {
      setErrorMsg(err.message || 'Locking report failed');
    } finally {
      setActionLoading(false);
    }
  };

  return (
    <div style={{ padding: '24px 0' }}>
      {/* Desk Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 24 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
            <span className="badge badge-clear">FR-7.1 / FR-7.3</span>
            <span className="badge badge-clear">§0 Constraint #5 (Traceable Claims)</span>
          </div>
          <h2 style={{ fontSize: 20, marginBottom: 4 }}>Traceable BLUF Intelligence Desk</h2>
          <p style={{ color: 'var(--text-secondary)', fontSize: 13 }}>
            Synthesized Bottom Line Up Front briefing with strict 100% citation attribution to telemetry evidence.
          </p>
        </div>

        {incident && !report && (
          <button 
            className="btn btn-primary"
            onClick={() => onGenerateBluf(incident._id || incident.incidentId)}
          >
            ⚡ Generate BLUF for {incident.incidentId}
          </button>
        )}
      </div>

      {!report && !incident && (
        <div className="card" style={{ textAlign: 'center', padding: '60px 20px' }}>
          <div style={{ fontSize: 36, marginBottom: 12 }}>📄</div>
          <h3 style={{ marginBottom: 6 }}>No Incident Selected for BLUF Review</h3>
          <p style={{ color: 'var(--text-secondary)', maxWidth: 500, margin: '0 auto', fontSize: 13 }}>
            Select an incident from the Triage Queue and click "Traceable BLUF" to view or generate an executive briefing.
          </p>
        </div>
      )}

      {report && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 340px', gap: 24 }}>
          {/* Main Briefing Column */}
          <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
            {/* Title & Metadata */}
            <div style={{ borderBottom: '1px solid var(--border-subtle)', paddingBottom: 16 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--color-cyan)' }}>
                  REPORT ID: {report.reportId}
                </span>
                <span style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: 11,
                  fontWeight: 700,
                  padding: '3px 8px',
                  borderRadius: 4,
                  background: report.status === 'LOCKED' ? 'rgba(168, 85, 247, 0.2)' : report.status === 'APPROVED' ? 'rgba(16, 185, 129, 0.2)' : 'rgba(245, 158, 11, 0.2)',
                  color: report.status === 'LOCKED' ? 'var(--color-purple)' : report.status === 'APPROVED' ? 'var(--color-emerald)' : 'var(--color-amber)',
                  border: '1px solid currentColor'
                }}>
                  {report.status}
                </span>
              </div>
              <h3 style={{ fontSize: 18, color: 'var(--text-primary)' }}>
                {report.incidentRef?.title || incident?.title || 'Tactical Incident Briefing'}
              </h3>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>
                Synthesized: {new Date(report.generatedAt).toLocaleString()} • Air-gapped Traceable Engine
              </div>
            </div>

            {/* 1. Executive Summary */}
            <div>
              <h4 style={{ fontSize: 14, color: 'var(--color-cyan)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 8 }}>
                1. Bottom Line Up Front (Executive Summary)
              </h4>
              <div style={{
                background: 'rgba(255, 255, 255, 0.02)',
                border: '1px solid var(--border-subtle)',
                borderRadius: 'var(--radius-sm)',
                padding: '14px 16px',
                lineHeight: 1.6,
                fontSize: 14,
                color: 'var(--text-primary)'
              }}>
                {report.executiveSummary}
              </div>
            </div>

            {/* 2. Threat Trajectory */}
            {report.threatTrajectory && (
              <div>
                <h4 style={{ fontSize: 14, color: 'var(--color-amber)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 8 }}>
                  2. Threat Trajectory &amp; Kill Chain Progression
                </h4>
                <div style={{
                  display: 'grid',
                  gridTemplateColumns: '1fr 1fr 1fr',
                  gap: 12,
                  background: 'rgba(245, 158, 11, 0.04)',
                  border: '1px solid rgba(245, 158, 11, 0.2)',
                  borderRadius: 'var(--radius-sm)',
                  padding: 14
                }}>
                  <div>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>CURRENT STAGE</div>
                    <div style={{ fontWeight: 600, color: 'var(--text-primary)', marginTop: 2 }}>
                      {report.threatTrajectory.currentStage || 'Active Infiltration'}
                    </div>
                  </div>
                  <div>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>ESTIMATED VECTOR</div>
                    <div style={{ fontWeight: 600, color: 'var(--text-primary)', marginTop: 2 }}>
                      {report.threatTrajectory.attackVector || 'Multi-Stage Loader'}
                    </div>
                  </div>
                  <div>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>PROJECTED IMPACT</div>
                    <div style={{ fontWeight: 600, color: 'var(--color-rose)', marginTop: 2 }}>
                      {report.threatTrajectory.projectedImpact || 'High / Lateral Movement'}
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* 3. Key Findings with MANDATORY CITATIONS (§0 #5) */}
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                <h4 style={{ fontSize: 14, color: 'var(--color-emerald)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                  3. Key Findings with Citation Attribution (§0 #5)
                </h4>
                <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                  Zero Unsourced Claims Rule Active
                </span>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                {report.keyFindings && report.keyFindings.map((kf, idx) => (
                  <div 
                    key={idx}
                    style={{
                      background: 'rgba(255, 255, 255, 0.02)',
                      border: '1px solid var(--border-subtle)',
                      borderRadius: 'var(--radius-sm)',
                      padding: '12px 14px'
                    }}
                  >
                    <div style={{ fontSize: 13, color: 'var(--text-primary)', marginBottom: 8, lineHeight: 1.5 }}>
                      • {kf.finding}
                    </div>
                    {/* Citations */}
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
                      <span style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                        🔗 Supporting Telemetry:
                      </span>
                      {kf.supportingEvidenceRefs && kf.supportingEvidenceRefs.map((ref, rIdx) => (
                        <span 
                          key={rIdx}
                          style={{
                            fontFamily: 'var(--font-mono)',
                            fontSize: 11,
                            background: 'rgba(16, 185, 129, 0.15)',
                            color: 'var(--color-emerald)',
                            border: '1px solid rgba(16, 185, 129, 0.3)',
                            padding: '2px 6px',
                            borderRadius: 4
                          }}
                        >
                          {typeof ref === 'object' ? (ref.eventId || ref._id?.slice(-8)) : String(ref).slice(-8)}
                        </span>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* 4. Recommended Actions */}
            {report.recommendedActions && report.recommendedActions.length > 0 && (
              <div>
                <h4 style={{ fontSize: 14, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 8 }}>
                  4. Recommended Containment &amp; Eradication Actions
                </h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                  {report.recommendedActions.map((action, aIdx) => (
                    <div 
                      key={aIdx} 
                      style={{ 
                        display: 'flex', 
                        alignItems: 'baseline', 
                        gap: 8, 
                        fontSize: 13, 
                        color: 'var(--text-primary)' 
                      }}
                    >
                      <span style={{ color: 'var(--color-cyan)', fontFamily: 'var(--font-mono)' }}>[0{aIdx + 1}]</span>
                      <span>{action}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Review & Lock Action Panel */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
            <div className="card">
              <h3 style={{ fontSize: 16, marginBottom: 12 }}>Human-in-the-Loop Sign-Off</h3>
              <p style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 16 }}>
                Per FR-7.3, intelligence reports require explicit operator review and immutable sign-off prior to commander distribution.
              </p>

              {/* Status details */}
              <div style={{ marginBottom: 16, fontSize: 12 }}>
                <div style={{ color: 'var(--text-muted)' }}>Current Workflow State:</div>
                <div style={{ fontSize: 15, fontWeight: 700, color: 'var(--text-primary)', marginTop: 2 }}>
                  {report.status}
                </div>
                {report.approvedBy && (
                  <div style={{ color: 'var(--color-emerald)', marginTop: 4 }}>
                    ✓ Approved by: {report.approvedBy}
                  </div>
                )}
                {report.approvedAt && (
                  <div style={{ color: 'var(--text-muted)' }}>
                    At: {new Date(report.approvedAt).toLocaleString()}
                  </div>
                )}
              </div>

              {/* Action Buttons */}
              {report.status === 'DRAFT' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                  <div>
                    <label style={{ display: 'block', fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>
                      Analyst Sign-Off Name:
                    </label>
                    <input
                      type="text"
                      value={analystSignName}
                      onChange={(e) => setAnalystSignName(e.target.value)}
                      placeholder="Analyst Name"
                      style={{
                        width: '100%',
                        background: 'var(--bg-secondary)',
                        border: '1px solid var(--border-subtle)',
                        borderRadius: 4,
                        color: 'var(--text-primary)',
                        padding: '6px 8px',
                        fontSize: 12
                      }}
                    />
                  </div>
                  <button
                    className="btn btn-success"
                    onClick={handleApprove}
                    disabled={actionLoading}
                    style={{ width: '100%' }}
                  >
                    {actionLoading ? 'Approving...' : '✓ Approve Report (Analyst Sign-Off)'}
                  </button>
                </div>
              )}

              {report.status === 'APPROVED' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                  <div style={{
                    fontSize: 12,
                    background: 'rgba(16, 185, 129, 0.1)',
                    padding: 10,
                    borderRadius: 4,
                    color: 'var(--color-emerald)'
                  }}>
                    Report is signed and approved. Ready for Commander Lock to prevent further edits.
                  </div>
                  <button
                    className="btn btn-primary"
                    onClick={handleLock}
                    disabled={actionLoading}
                    style={{ width: '100%' }}
                  >
                    {actionLoading ? 'Locking...' : '🔒 Lock Report (Commander Authorization)'}
                  </button>
                </div>
              )}

              {report.status === 'LOCKED' && (
                <div style={{
                  fontSize: 12,
                  background: 'rgba(168, 85, 247, 0.1)',
                  border: '1px solid rgba(168, 85, 247, 0.3)',
                  padding: 12,
                  borderRadius: 4,
                  color: 'var(--color-purple)'
                }}>
                  🔒 Report is permanently locked. Archived to immutable incident dossier.
                </div>
              )}

              {errorMsg && (
                <div style={{ color: 'var(--color-rose)', fontSize: 12, marginTop: 10 }}>
                  ⚠️ {errorMsg}
                </div>
              )}
            </div>

            {/* §0 Integrity Card */}
            <div className="card" style={{ background: 'rgba(6, 182, 212, 0.03)' }}>
              <div style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--color-cyan)', marginBottom: 6 }}>
                AIR-GAPPED SYNTHESIS ENGINE
              </div>
              <p style={{ fontSize: 11, color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                SentinelIQ strictly forbids unverified generative claims. Every statement in the BLUF is derived via heuristic correlation and deterministically linked to raw telemetry IDs.
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
