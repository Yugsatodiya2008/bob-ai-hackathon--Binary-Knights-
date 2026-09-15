const BlufReport = require('../models/BlufReport');
const Incident = require('../models/Incident');
const NormalizedEvent = require('../models/NormalizedEvent');
const { v4: uuidv4 } = require('uuid');

// ============================================================================
// FR-7.1 / FR-7.2: BLUF Auto-Generation with Citation Linking
// §0 #5: Every keyFinding.statement MUST have non-empty supportingEvidenceRefs
//         pointing at real normalized_events IDs. No unsourced claims.
// ============================================================================

const generateBluf = async (incidentId) => {
  const incident = await Incident.findById(incidentId).populate('eventRefs');
  if (!incident) throw new Error('Incident not found');

  const events = incident.eventRefs;
  if (!events || events.length === 0) {
    throw new Error('Cannot generate BLUF: incident has no linked events');
  }

  // Build the executive summary from incident data
  const executiveSummary = buildExecutiveSummary(incident, events);

  // Build key findings — each one MUST reference real event IDs
  const keyFindings = buildKeyFindings(incident, events);

  // Validate §0 #5: No unsourced claims
  for (const finding of keyFindings) {
    if (!finding.supportingEvidenceRefs || finding.supportingEvidenceRefs.length === 0) {
      throw new Error(`§0 Constraint Violation: BLUF finding "${finding.statement}" has no supporting evidence refs`);
    }
    // Verify each ref exists in normalized_events
    for (const ref of finding.supportingEvidenceRefs) {
      const exists = await NormalizedEvent.findById(ref);
      if (!exists) {
        throw new Error(`§0 Constraint Violation: BLUF evidence ref ${ref} does not exist in normalized_events`);
      }
    }
  }

  // Build recommended actions
  const recommendedActions = buildRecommendedActions(incident);

  const report = await BlufReport.create({
    reportId: `BLUF-${new Date().getFullYear()}-${uuidv4().slice(0, 8).toUpperCase()}`,
    incidentRef: incident._id,
    executiveSummary,
    keyFindings,
    threatActorAttribution: {
      actorName: 'UNKNOWN / UNATTRIBUTED',
      confidence: 0,
      evidenceRefs: []
    },
    recommendedActions,
    status: 'DRAFT'
  });

  return report;
};

const buildExecutiveSummary = (incident, events) => {
  const sources = [...new Set(events.map(e => e.source))].join(', ');
  const ips = [...new Set(events.map(e => e.sourceIp).filter(Boolean))].join(', ');
  const techniques = incident.mitreAttack.map(m => `${m.techniqueName} (${m.techniqueId})`).join(', ') || 'Pending ATT&CK mapping';

  return `BOTTOM LINE: ${incident.title}. ` +
    `This incident has a confidence score of ${incident.confidenceScore}/100 and priority score of ${incident.priorityScore}/100. ` +
    `It is correlated from ${events.length} event(s) across source(s): ${sources}. ` +
    `Affected IP(s): ${ips || 'N/A'}. ` +
    `Mapped ATT&CK techniques: ${techniques}. ` +
    `Current status: ${incident.status}. TLP: ${incident.tlp}.`;
};

const buildKeyFindings = (incident, events) => {
  const findings = [];

  // Finding 1: Primary threat detection — always cite the first/primary event
  const primaryEvent = events[0];
  findings.push({
    statement: `Primary threat detection from ${primaryEvent.source}: ` +
      `${primaryEvent.eventType} event (ID: ${primaryEvent.eventId}) ` +
      `with severity ${primaryEvent.severity} at ${primaryEvent.timestamp.toISOString()}.`,
    supportingEvidenceRefs: [primaryEvent._id]
  });

  // Finding 2: If multiple events, note the correlation pattern
  if (events.length > 1) {
    findings.push({
      statement: `Multi-source correlation: ${events.length} events correlated by shared IOCs ` +
        `across ${[...new Set(events.map(e => e.source))].join(', ')} within a ${getTimeSpan(events)} window.`,
      supportingEvidenceRefs: events.map(e => e._id)
    });
  }

  // Finding 3: MITRE ATT&CK technique findings
  if (incident.mitreAttack && incident.mitreAttack.length > 0) {
    const techniqueList = incident.mitreAttack.map(m => `${m.techniqueName} (${m.techniqueId})`).join('; ');
    findings.push({
      statement: `ATT&CK techniques identified: ${techniqueList}. ` +
        `These map to tactics including ${[...new Set(incident.mitreAttack.map(m => m.tactic))].join(', ')}.`,
      supportingEvidenceRefs: events.map(e => e._id)
    });
  }

  // Finding 4: High-severity or critical indicators
  const criticalEvents = events.filter(e => e.severity === 'CRITICAL' || e.severity === 'HIGH');
  if (criticalEvents.length > 0) {
    findings.push({
      statement: `${criticalEvents.length} event(s) flagged at HIGH/CRITICAL severity requiring immediate analyst attention.`,
      supportingEvidenceRefs: criticalEvents.map(e => e._id)
    });
  }

  return findings;
};

const buildRecommendedActions = (incident) => {
  const actions = [];

  if (incident.severity === 'CRITICAL') {
    actions.push({ action: 'Immediately isolate affected host(s) from the network', priority: 'IMMEDIATE', requiresApproval: true });
    actions.push({ action: 'Initiate forensic imaging of affected systems', priority: 'IMMEDIATE', requiresApproval: true });
  }
  if (incident.severity === 'HIGH' || incident.severity === 'CRITICAL') {
    actions.push({ action: 'Escalate to incident response team lead', priority: 'HIGH', requiresApproval: false });
    actions.push({ action: 'Review and block associated IOCs at perimeter', priority: 'HIGH', requiresApproval: true });
  }
  actions.push({ action: 'Document findings and update case file', priority: 'ROUTINE', requiresApproval: false });

  return actions;
};

const getTimeSpan = (events) => {
  const times = events.map(e => e.timestamp.getTime()).sort();
  const spanMs = times[times.length - 1] - times[0];
  const hours = Math.round(spanMs / (1000 * 60 * 60) * 10) / 10;
  return hours < 1 ? `${Math.round(spanMs / (1000 * 60))} minute(s)` : `${hours} hour(s)`;
};

// FR-7.3: Approve/Lock workflow — requires human analyst
const approveBluf = async (reportId, analystName) => {
  if (!analystName) {
    throw new Error('§0 Constraint: BLUF approval requires analyst name (human-in-the-loop)');
  }

  const report = await BlufReport.findOne({ reportId });
  if (!report) throw new Error('BLUF report not found');

  if (report.status === 'LOCKED') {
    throw new Error('Report is already locked and cannot be modified');
  }

  report.status = 'APPROVED';
  report.approvedBy = analystName;
  report.approvedAt = new Date();
  await report.save();
  return report;
};

const lockBluf = async (reportId) => {
  const report = await BlufReport.findOne({ reportId });
  if (!report) throw new Error('BLUF report not found');
  if (report.status !== 'APPROVED') {
    throw new Error('Only APPROVED reports can be locked. Current status: ' + report.status);
  }

  report.status = 'LOCKED';
  await report.save();
  return report;
};

module.exports = {
  generateBluf,
  approveBluf,
  lockBluf,
  buildExecutiveSummary,
  buildKeyFindings,
  buildRecommendedActions
};
