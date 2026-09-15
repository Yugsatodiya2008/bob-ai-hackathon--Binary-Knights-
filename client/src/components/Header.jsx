import React from 'react';

export default function Header({ 
  currentUser, 
  onUserChange, 
  onRunPipeline, 
  onIngestSample, 
  pipelineRunning, 
  stats 
}) {
  return (
    <header style={{
      borderBottom: '1px solid var(--border-subtle)',
      background: 'rgba(8, 13, 26, 0.9)',
      backdropFilter: 'blur(16px)',
      position: 'sticky',
      top: 0,
      zIndex: 100,
      padding: '12px 28px'
    }}>
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        maxWidth: 1600,
        margin: '0 auto'
      }}>
        {/* Logo & Title */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
          <div style={{
            width: 38,
            height: 38,
            borderRadius: 10,
            background: 'linear-gradient(135deg, #06b6d4 0%, #3b82f6 100%)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            boxShadow: '0 0 15px rgba(6, 182, 212, 0.4)'
          }}>
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#040814" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              <path d="m9 12 2 2 4-4" />
            </svg>
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{
                fontFamily: 'var(--font-heading)',
                fontSize: 20,
                fontWeight: 700,
                letterSpacing: '-0.02em',
                background: 'linear-gradient(90deg, #f1f5f9 0%, #06b6d4 100%)',
                WebkitBackgroundClip: 'text',
                WebkitTextFillColor: 'transparent'
              }}>SentinelIQ</span>
              <span style={{
                fontSize: 10,
                fontFamily: 'var(--font-mono)',
                background: 'rgba(6, 182, 212, 0.15)',
                color: 'var(--color-cyan)',
                padding: '2px 6px',
                borderRadius: 4,
                border: '1px solid rgba(6, 182, 212, 0.3)'
              }}>v1.0 DEFENSE</span>
            </div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
              Threat Intelligence Correlation &amp; Prioritisation Assistant
            </div>
          </div>
        </div>

        {/* Global Live Telemetry Quick Stats */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 20 }}>
          <div style={{ textAlign: 'right' }}>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Correlated Incidents
            </div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 16, fontWeight: 700, color: 'var(--color-cyan)' }}>
              {stats.incidentCount}
            </div>
          </div>
          <div style={{ width: 1, height: 28, background: 'var(--border-subtle)' }} />
          <div style={{ textAlign: 'right' }}>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Quarantined
            </div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 16, fontWeight: 700, color: stats.quarantineCount > 0 ? 'var(--color-amber)' : 'var(--text-secondary)' }}>
              {stats.quarantineCount}
            </div>
          </div>
          <div style={{ width: 1, height: 28, background: 'var(--border-subtle)' }} />
          <div style={{ textAlign: 'right' }}>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Avg Confidence
            </div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 16, fontWeight: 700, color: 'var(--color-emerald)' }}>
              {stats.avgConfidence}%
            </div>
          </div>
        </div>

        {/* User Clearance Simulator & Action Buttons */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          {/* Persona Switcher for Live TLP / RBAC Demo */}
          <div style={{
            background: 'var(--bg-secondary)',
            border: '1px solid var(--border-subtle)',
            borderRadius: 'var(--radius-sm)',
            padding: '4px 10px',
            display: 'flex',
            alignItems: 'center',
            gap: 8
          }}>
            <span style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Analyst:</span>
            <select
              value={currentUser.preset}
              onChange={(e) => onUserChange(e.target.value)}
              style={{
                background: 'transparent',
                border: 'none',
                color: 'var(--text-primary)',
                fontFamily: 'var(--font-sans)',
                fontSize: 12,
                cursor: 'pointer',
                outline: 'none'
              }}
            >
              <option value="analyst_red">Sarah Vance (Lead Analyst - TLP:RED)</option>
              <option value="analyst_amber">Alex Chen (Analyst - TLP:AMBER)</option>
              <option value="analyst_green">Junior Trainee (Analyst - TLP:GREEN)</option>
              <option value="commander_red">Cdr. Morrison (Commander - TLP:RED)</option>
              <option value="admin">System Admin (Audit &amp; Quarantine)</option>
            </select>
            <span className={`badge badge-${currentUser.clearance.toLowerCase().replace('_', '-')}`}>
              TLP:{currentUser.clearance}
            </span>
          </div>

          {/* Quick Attack Simulator Trigger */}
          <button
            className="btn btn-secondary btn-sm"
            onClick={onIngestSample}
            title="Inject simulated APT attack telemetry"
          >
            ⚡ Ingest Telemetry
          </button>

          {/* Pipeline Run Button */}
          <button
            className="btn btn-primary btn-sm"
            onClick={onRunPipeline}
            disabled={pipelineRunning}
          >
            {pipelineRunning ? '⚙️ Running Pipeline...' : '▶ Run Pipeline'}
          </button>
        </div>
      </div>
    </header>
  );
}
