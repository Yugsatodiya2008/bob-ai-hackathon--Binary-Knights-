import React, { useState, useEffect, useCallback } from 'react';
import Header from './components/Header';
import TriageQueue from './components/TriageQueue';
import IncidentDetailModal from './components/IncidentDetailModal';
import ExplainabilityModal from './components/ExplainabilityModal';
import BlufDesk from './components/BlufDesk';
import MitreHeatmap from './components/MitreHeatmap';
import QuarantineManager from './components/QuarantineManager';
import AuditLogViewer from './components/AuditLogViewer';

export default function App() {
  // Current user persona for RBAC & TLP clearance
  const [currentUser, setCurrentUser] = useState({
    name: 'Sarah Vance',
    email: 'sarah.vance@soc.sentineliq.internal',
    role: 'ANALYST',
    clearance: 'AMBER'
  });

  // Navigation tabs: 'triage' | 'bluf' | 'mitre' | 'quarantine' | 'audit'
  const [activeTab, setActiveTab] = useState('triage');

  // Application data states
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(false);
  const [pipelineRunning, setPipelineRunning] = useState(false);
  const [stats, setStats] = useState({
    criticalCount: 0,
    amberCount: 0,
    quarantineCount: 0
  });

  // Modals state
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [explainIncident, setExplainIncident] = useState(null);

  // BLUF Desk state
  const [blufIncident, setBlufIncident] = useState(null);
  const [blufReport, setBlufReport] = useState(null);

  // MITRE state
  const [mitreHeatmapData, setMitreHeatmapData] = useState(null);

  // Notification Toast state
  const [toast, setToast] = useState(null);

  const showToast = (message, type = 'info') => {
    setToast({ message, type });
    setTimeout(() => {
      setToast(null);
    }, 4500);
  };

  // 1. Fetch Incidents (TLP Query-layer filtered by currentUser)
  const fetchIncidents = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/v1/triage', {
        headers: {
          'x-user-role': currentUser.role,
          'x-user-clearance': currentUser.clearance,
          'x-user-email': currentUser.email
        }
      });
      const data = await res.json();
      if (data.success) {
        setIncidents(data.data || []);
      } else {
        showToast(data.error || 'Failed to load triage queue', 'error');
      }
    } catch (err) {
      console.error('Error fetching triage:', err);
      showToast('Network error loading triage queue', 'error');
    } finally {
      setLoading(false);
    }
  }, [currentUser]);

  // 2. Fetch Global Stats & Counts
  const fetchStats = useCallback(async () => {
    try {
      // Quarantine count
      const qRes = await fetch('/api/v1/quarantine', {
        headers: {
          'x-user-role': currentUser.role,
          'x-user-clearance': currentUser.clearance,
          'x-user-email': currentUser.email
        }
      });
      const qData = await qRes.json();
      const quarantineCount = qData.success && Array.isArray(qData.data) ? qData.data.length : 0;

      // Calculate critical & amber from incidents
      const criticalCount = incidents.filter(i => (i.riskScore?.finalPriorityScore || 0) >= 80).length;
      const amberCount = incidents.filter(i => (i.riskScore?.finalPriorityScore || 0) >= 50 && (i.riskScore?.finalPriorityScore || 0) < 80).length;

      setStats({
        criticalCount,
        amberCount,
        quarantineCount
      });
    } catch (err) {
      console.error('Error calculating stats:', err);
    }
  }, [currentUser, incidents]);

  // 3. Fetch MITRE Heatmap Matrix
  const fetchMitreHeatmap = useCallback(async () => {
    try {
      const res = await fetch('/api/v1/mitre/matrix', {
        headers: {
          'x-user-role': currentUser.role,
          'x-user-clearance': currentUser.clearance
        }
      });
      const data = await res.json();
      if (data.success) {
        setMitreHeatmapData(data.data);
      }
    } catch (err) {
      console.error('Error loading MITRE heatmap:', err);
    }
  }, [currentUser]);

  // Trigger data reload whenever user switches clearance/persona
  useEffect(() => {
    fetchIncidents();
    fetchMitreHeatmap();
  }, [fetchIncidents, fetchMitreHeatmap]);

  useEffect(() => {
    fetchStats();
  }, [incidents, fetchStats]);

  // Handle Pipeline Run
  const handleRunPipeline = async () => {
    setPipelineRunning(true);
    showToast('Executing Correlation & Scoring Pipeline (FR-4, FR-5)...', 'info');
    try {
      const res = await fetch('/api/v1/pipeline/run', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-user-role': currentUser.role,
          'x-user-clearance': currentUser.clearance,
          'x-user-email': currentUser.email
        }
      });
      const data = await res.json();
      if (data.success) {
        showToast(`Pipeline completed: ${data.data?.correlatedIncidents || 0} incidents prioritized`, 'success');
        await fetchIncidents();
        await fetchMitreHeatmap();
      } else {
        showToast(data.error || 'Pipeline execution failed', 'error');
      }
    } catch (err) {
      showToast('Network error during pipeline execution', 'error');
    } finally {
      setPipelineRunning(false);
    }
  };

  // Handle Sample Ingestion (Simulate Raw Ingestion Event)
  const handleIngestSample = async () => {
    showToast('Ingesting synthetic high-confidence multi-source threat alert...', 'info');
    try {
      const sampleEvent = {
        source: 'CrowdStrike-Falcon',
        sourceType: 'EDR',
        rawPayload: {
          event_type: 'SuspiciousProcessExecution',
          sha256: 'a9f2c8423e8e19b5e586b627b13c7c2be95a15324b162629b3f46f3459c23947',
          process: 'powershell.exe -enc JABzACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQA...',
          host: 'FINANCE-SRV-01',
          user: 'adm_service_sql',
          src_ip: '192.168.10.45',
          dst_ip: '194.26.29.112',
          tlp: 'AMBER'
        }
      };

      const res = await fetch('/api/v1/ingest', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-user-role': currentUser.role,
          'x-user-clearance': currentUser.clearance,
          'x-user-email': currentUser.email
        },
        body: JSON.stringify(sampleEvent)
      });
      const data = await res.json();
      if (data.success) {
        showToast('Sample event ingested and normalized! Running correlation...', 'success');
        await handleRunPipeline();
      } else {
        showToast(data.error || 'Ingestion failed', 'error');
      }
    } catch (err) {
      showToast('Ingestion network error', 'error');
    }
  };

  // Status update handler (strictly respects §0 Constraint #1)
  const handleStatusUpdate = async (incidentId, payload) => {
    try {
      const res = await fetch(`/api/v1/incidents/${incidentId}/status`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          'x-user-role': currentUser.role,
          'x-user-clearance': currentUser.clearance,
          'x-user-email': currentUser.email
        },
        body: JSON.stringify(payload)
      });
      const data = await res.json();
      if (data.success) {
        showToast(`Incident status updated to ${payload.status} with analyst sign-off recorded.`, 'success');
        setSelectedIncident(null);
        await fetchIncidents();
      } else {
        throw new Error(data.error || 'Failed to update status');
      }
    } catch (err) {
      showToast(err.message || 'Status update failed', 'error');
      throw err;
    }
  };

  // BLUF generation handler
  const handleGenerateBluf = async (incidentId) => {
    try {
      showToast('Synthesizing executive BLUF report with citation links...', 'info');
      const res = await fetch('/api/v1/bluf/generate', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-user-role': currentUser.role,
          'x-user-clearance': currentUser.clearance,
          'x-user-email': currentUser.email
        },
        body: JSON.stringify({ incidentId })
      });
      const data = await res.json();
      if (data.success) {
        setBlufReport(data.data);
        showToast('BLUF Report generated in DRAFT state. Awaiting analyst sign-off.', 'success');
      } else {
        showToast(data.error || 'Failed to generate BLUF', 'error');
      }
    } catch (err) {
      showToast('Failed to generate BLUF', 'error');
    }
  };

  // BLUF approval handler
  const handleApproveBluf = async (reportId, analystName) => {
    const res = await fetch(`/api/v1/bluf/${reportId}/approve`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-user-role': currentUser.role,
        'x-user-clearance': currentUser.clearance,
        'x-user-email': currentUser.email
      },
      body: JSON.stringify({ analystName })
    });
    const data = await res.json();
    if (data.success) {
      setBlufReport(data.data);
      showToast(`BLUF Report approved by ${analystName}`, 'success');
    } else {
      throw new Error(data.error || 'Approval failed');
    }
  };

  // BLUF lock handler
  const handleLockBluf = async (reportId) => {
    const res = await fetch(`/api/v1/bluf/${reportId}/lock`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-user-role': currentUser.role,
        'x-user-clearance': currentUser.clearance,
        'x-user-email': currentUser.email
      }
    });
    const data = await res.json();
    if (data.success) {
      setBlufReport(data.data);
      showToast('BLUF Report locked as immutable final release.', 'success');
    } else {
      throw new Error(data.error || 'Lock failed');
    }
  };

  // Open BLUF Desk for a specific incident
  const handleOpenBlufForIncident = async (inc) => {
    setSelectedIncident(null);
    setBlufIncident(inc);
    setActiveTab('bluf');

    // Attempt to load existing BLUF for this incident
    try {
      const res = await fetch(`/api/v1/bluf/incident/${inc._id || inc.incidentId}`, {
        headers: {
          'x-user-role': currentUser.role,
          'x-user-clearance': currentUser.clearance,
          'x-user-email': currentUser.email
        }
      });
      const data = await res.json();
      if (data.success && data.data) {
        setBlufReport(data.data);
      } else {
        setBlufReport(null);
      }
    } catch (err) {
      setBlufReport(null);
    }
  };

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column', background: 'var(--bg-app)' }}>
      {/* Toast Notification */}
      {toast && (
        <div style={{
          position: 'fixed',
          bottom: 24,
          right: 24,
          zIndex: 9999,
          padding: '12px 20px',
          borderRadius: 'var(--radius-md)',
          background: toast.type === 'error' ? 'rgba(239, 68, 68, 0.95)' :
                      toast.type === 'success' ? 'rgba(16, 185, 129, 0.95)' :
                      'rgba(6, 182, 212, 0.95)',
          color: '#ffffff',
          boxShadow: '0 8px 24px rgba(0, 0, 0, 0.5)',
          fontWeight: 500,
          fontSize: 13,
          display: 'flex',
          alignItems: 'center',
          gap: 10,
          backdropFilter: 'blur(8px)',
          animation: 'fadeIn 0.2s ease-out'
        }}>
          <span>{toast.type === 'error' ? '⚠️' : toast.type === 'success' ? '✓' : 'ℹ️'}</span>
          <span>{toast.message}</span>
        </div>
      )}

      {/* Global SOC Commander Header */}
      <Header 
        currentUser={currentUser}
        onUserChange={setCurrentUser}
        onRunPipeline={handleRunPipeline}
        onIngestSample={handleIngestSample}
        pipelineRunning={pipelineRunning}
        stats={stats}
      />

      {/* Main Tab Navigation Bar */}
      <nav style={{
        background: 'rgba(10, 16, 31, 0.85)',
        borderBottom: '1px solid var(--border-subtle)',
        padding: '0 28px'
      }}>
        <div style={{
          maxWidth: 1600,
          margin: '0 auto',
          display: 'flex',
          gap: 6
        }}>
          <button
            onClick={() => setActiveTab('triage')}
            style={{
              padding: '12px 18px',
              border: 'none',
              background: 'transparent',
              color: activeTab === 'triage' ? 'var(--color-cyan)' : 'var(--text-secondary)',
              borderBottom: activeTab === 'triage' ? '2px solid var(--color-cyan)' : '2px solid transparent',
              cursor: 'pointer',
              fontWeight: 600,
              fontSize: 13,
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              transition: 'all 0.15s ease'
            }}
          >
            <span>🎯 Triage Queue</span>
            <span style={{
              background: 'rgba(255, 255, 255, 0.08)',
              padding: '2px 7px',
              borderRadius: 10,
              fontSize: 11
            }}>{incidents.length}</span>
          </button>

          <button
            onClick={() => setActiveTab('bluf')}
            style={{
              padding: '12px 18px',
              border: 'none',
              background: 'transparent',
              color: activeTab === 'bluf' ? 'var(--color-cyan)' : 'var(--text-secondary)',
              borderBottom: activeTab === 'bluf' ? '2px solid var(--color-cyan)' : '2px solid transparent',
              cursor: 'pointer',
              fontWeight: 600,
              fontSize: 13,
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              transition: 'all 0.15s ease'
            }}
          >
            <span>📄 BLUF Intelligence Desk</span>
            {blufIncident && (
              <span style={{
                background: 'rgba(6, 182, 212, 0.2)',
                color: 'var(--color-cyan)',
                padding: '2px 7px',
                borderRadius: 10,
                fontSize: 11
              }}>Active</span>
            )}
          </button>

          <button
            onClick={() => setActiveTab('mitre')}
            style={{
              padding: '12px 18px',
              border: 'none',
              background: 'transparent',
              color: activeTab === 'mitre' ? 'var(--color-cyan)' : 'var(--text-secondary)',
              borderBottom: activeTab === 'mitre' ? '2px solid var(--color-cyan)' : '2px solid transparent',
              cursor: 'pointer',
              fontWeight: 600,
              fontSize: 13,
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              transition: 'all 0.15s ease'
            }}
          >
            <span>🗺️ ATT&CK Heatmap</span>
            <span className="badge badge-clear" style={{ fontSize: 10 }}>FR-5.3</span>
          </button>

          <button
            onClick={() => setActiveTab('quarantine')}
            style={{
              padding: '12px 18px',
              border: 'none',
              background: 'transparent',
              color: activeTab === 'quarantine' ? 'var(--color-amber)' : 'var(--text-secondary)',
              borderBottom: activeTab === 'quarantine' ? '2px solid var(--color-amber)' : '2px solid transparent',
              cursor: 'pointer',
              fontWeight: 600,
              fontSize: 13,
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              transition: 'all 0.15s ease'
            }}
          >
            <span>⚠️ Ingestion Quarantine</span>
            <span style={{
              background: stats.quarantineCount > 0 ? 'rgba(245, 158, 11, 0.2)' : 'rgba(255, 255, 255, 0.08)',
              color: stats.quarantineCount > 0 ? 'var(--color-amber)' : 'inherit',
              padding: '2px 7px',
              borderRadius: 10,
              fontSize: 11
            }}>{stats.quarantineCount}</span>
          </button>

          <button
            onClick={() => setActiveTab('audit')}
            style={{
              padding: '12px 18px',
              border: 'none',
              background: 'transparent',
              color: activeTab === 'audit' ? 'var(--color-purple)' : 'var(--text-secondary)',
              borderBottom: activeTab === 'audit' ? '2px solid var(--color-purple)' : '2px solid transparent',
              cursor: 'pointer',
              fontWeight: 600,
              fontSize: 13,
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              transition: 'all 0.15s ease'
            }}
          >
            <span>📜 SOC Audit Trail</span>
            <span className="badge badge-purple" style={{ fontSize: 10 }}>§0 Strict</span>
          </button>
        </div>
      </nav>

      {/* Main Content Area */}
      <main style={{
        flex: 1,
        maxWidth: 1600,
        width: '100%',
        margin: '0 auto',
        padding: '0 28px 48px'
      }}>
        {activeTab === 'triage' && (
          <TriageQueue 
            incidents={incidents}
            userClearance={currentUser.clearance}
            onSelectIncident={setSelectedIncident}
            onExplainScore={setExplainIncident}
            onOpenBluf={handleOpenBlufForIncident}
            loading={loading}
          />
        )}

        {activeTab === 'bluf' && (
          <div style={{ padding: '24px 0' }}>
            <BlufDesk 
              incident={blufIncident || incidents[0]}
              report={blufReport}
              onGenerateBluf={handleGenerateBluf}
              onApproveBluf={handleApproveBluf}
              onLockBluf={handleLockBluf}
              currentUser={currentUser}
            />
          </div>
        )}

        {activeTab === 'mitre' && (
          <MitreHeatmap 
            heatmapData={mitreHeatmapData}
            onSelectTechnique={(tech) => {
              showToast(`Selected technique: ${tech.techniqueId} - ${tech.techniqueName}`, 'info');
            }}
          />
        )}

        {activeTab === 'quarantine' && (
          <QuarantineManager 
            currentUser={currentUser}
            onReloadStats={fetchStats}
          />
        )}

        {activeTab === 'audit' && (
          <AuditLogViewer 
            currentUser={currentUser}
          />
        )}
      </main>

      {/* Incident Detail Modal */}
      {selectedIncident && (
        <IncidentDetailModal 
          incident={selectedIncident}
          onClose={() => setSelectedIncident(null)}
          currentUser={currentUser}
          onStatusUpdate={handleStatusUpdate}
          onOpenBluf={handleOpenBlufForIncident}
        />
      )}

      {/* Explainable Scoring Factors Modal (§0 Constraint #2) */}
      {explainIncident && (
        <ExplainabilityModal 
          incident={explainIncident}
          onClose={() => setExplainIncident(null)}
        />
      )}

      {/* Footer System Status */}
      <footer style={{
        borderTop: '1px solid var(--border-subtle)',
        background: 'rgba(8, 13, 26, 0.95)',
        padding: '12px 28px',
        fontSize: 12,
        color: 'var(--text-muted)'
      }}>
        <div style={{
          maxWidth: 1600,
          margin: '0 auto',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
            <span>SentinelIQ v1.0 MERN Autonomous Defense Slice</span>
            <span>•</span>
            <span style={{ color: 'var(--color-emerald)' }}>● All §0 Constraints Enforced</span>
            <span>•</span>
            <span>Air-Gapped Telemetry Engine Active</span>
          </div>
          <div>
            Logged in as <strong style={{ color: 'var(--text-primary)' }}>{currentUser.name}</strong> ({currentUser.role} | TLP:{currentUser.clearance})
          </div>
        </div>
      </footer>
    </div>
  );
}
