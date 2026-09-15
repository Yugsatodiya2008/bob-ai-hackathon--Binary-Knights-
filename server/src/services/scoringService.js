const NormalizedEvent = require('../models/NormalizedEvent');
const Incident = require('../models/Incident');

// ============================================================================
// FR-4.1 / FR-4.2: Confidence Scoring Engine with Explainability
// Every score MUST return contributing factors alongside the score (§0 #2)
// ============================================================================

const SOURCE_FIDELITY = {
  crowdstrike: 90,
  suricata: 80,
  splunkevent: 70,
  generic_webhook: 55
};

const computeConfidenceScore = async (incident) => {
  const events = await NormalizedEvent.find({ _id: { $in: incident.eventRefs } });
  if (events.length === 0) {
    return {
      score: 0,
      factors: [{ factor: 'NO_EVENTS', weight: 1.0, score: 0, reason: 'Incident has no linked events' }]
    };
  }

  const factors = [];

  // Factor 1: Source fidelity (average of all event source scores)
  const fidelityScores = events.map(e => SOURCE_FIDELITY[e.source] || 50);
  const avgFidelity = fidelityScores.reduce((a, b) => a + b, 0) / fidelityScores.length;
  factors.push({
    factor: 'SOURCE_FIDELITY',
    weight: 0.3,
    score: Math.round(avgFidelity),
    reason: `Average source fidelity across ${events.length} event(s) from [${[...new Set(events.map(e => e.source))].join(', ')}]`
  });

  // Factor 2: Multi-source corroboration
  const uniqueSources = new Set(events.map(e => e.source));
  const corroborationScore = uniqueSources.size >= 3 ? 100 : uniqueSources.size === 2 ? 85 : 60;
  factors.push({
    factor: 'MULTI_SOURCE_CORROBORATION',
    weight: 0.25,
    score: corroborationScore,
    reason: `${uniqueSources.size} distinct source(s) corroborate this incident: [${[...uniqueSources].join(', ')}]`
  });

  // Factor 3: Temporal clustering (events within a tight window = higher confidence)
  const timestamps = events.map(e => e.timestamp.getTime()).sort();
  let clusterScore = 50;
  if (timestamps.length > 1) {
    const spanHours = (timestamps[timestamps.length - 1] - timestamps[0]) / (1000 * 60 * 60);
    if (spanHours <= 1) clusterScore = 95;
    else if (spanHours <= 6) clusterScore = 80;
    else if (spanHours <= 24) clusterScore = 65;
    else clusterScore = 40;
  }
  factors.push({
    factor: 'TEMPORAL_CLUSTERING',
    weight: 0.2,
    score: clusterScore,
    reason: timestamps.length > 1
      ? `${events.length} events spanning ${((timestamps[timestamps.length - 1] - timestamps[0]) / (1000 * 60 * 60)).toFixed(1)} hours`
      : 'Single event — no temporal clustering data'
  });

  // Factor 4: IOC richness (how many distinct IOC types present)
  const iocTypes = new Set();
  events.forEach(e => {
    if (e.sourceIp) iocTypes.add('sourceIp');
    if (e.destinationIp) iocTypes.add('destinationIp');
    if (e.fileHash) iocTypes.add('fileHash');
    if (e.domain) iocTypes.add('domain');
    if (e.user) iocTypes.add('user');
    if (e.processName) iocTypes.add('processName');
  });
  const iocScore = Math.min(100, iocTypes.size * 20);
  factors.push({
    factor: 'IOC_RICHNESS',
    weight: 0.15,
    score: iocScore,
    reason: `${iocTypes.size} distinct IOC types present: [${[...iocTypes].join(', ')}]`
  });

  // Factor 5: Severity alignment
  const severityRanks = { CRITICAL: 100, HIGH: 80, MEDIUM: 50, LOW: 25 };
  const maxSevScore = Math.max(...events.map(e => severityRanks[e.severity] || 50));
  factors.push({
    factor: 'SEVERITY_ALIGNMENT',
    weight: 0.1,
    score: maxSevScore,
    reason: `Highest severity in event cluster: ${events.find(e => (severityRanks[e.severity] || 50) === maxSevScore)?.severity || 'MEDIUM'}`
  });

  // Compute weighted score
  const totalWeight = factors.reduce((sum, f) => sum + f.weight, 0);
  const weightedScore = factors.reduce((sum, f) => sum + f.weight * f.score, 0) / totalWeight;
  const finalScore = Math.round(Math.min(100, Math.max(0, weightedScore)));

  return { score: finalScore, factors };
};

// ============================================================================
// FR-6.1 / FR-6.2: Priority Scoring Engine with Explainability
// ============================================================================

const computePriorityScore = async (incident) => {
  const events = await NormalizedEvent.find({ _id: { $in: incident.eventRefs } });
  const factors = [];

  // Factor 1: Severity-based urgency
  const severityRanks = { CRITICAL: 95, HIGH: 75, MEDIUM: 45, LOW: 20 };
  const maxSev = Math.max(...events.map(e => severityRanks[e.severity] || 45), 45);
  factors.push({
    factor: 'SEVERITY_URGENCY',
    weight: 0.3,
    score: maxSev,
    reason: `Incident maximum severity yields urgency score ${maxSev}`
  });

  // Factor 2: Asset criticality heuristic (domain controllers, servers, admin users)
  let assetScore = 40;
  const assetReasons = [];
  const allUsers = events.map(e => e.user).filter(Boolean);
  const allIps = events.map(e => e.sourceIp).filter(Boolean);
  const allProcesses = events.map(e => e.processName).filter(Boolean);

  if (allUsers.some(u => /admin|root|system|domain/i.test(u))) {
    assetScore = 95;
    assetReasons.push('Privileged user account involved');
  }
  if (allProcesses.some(p => /lsass|mimikatz|psexec|cmd\.exe|powershell/i.test(p))) {
    assetScore = Math.max(assetScore, 90);
    assetReasons.push('High-risk process detected');
  }
  if (allIps.some(ip => /^10\.0\.0\.(1|2|3|10|11)$/.test(ip))) {
    assetScore = Math.max(assetScore, 85);
    assetReasons.push('Critical infrastructure IP range');
  }
  if (assetReasons.length === 0) assetReasons.push('Standard asset classification');
  factors.push({
    factor: 'ASSET_CRITICALITY',
    weight: 0.25,
    score: assetScore,
    reason: assetReasons.join('; ')
  });

  // Factor 3: Data sensitivity (TLP level)
  const tlpScores = { RED: 100, AMBER_STRICT: 90, AMBER: 70, GREEN: 40, CLEAR: 20 };
  const maxTlpScore = Math.max(...events.map(e => tlpScores[e.tlp] || 70));
  factors.push({
    factor: 'DATA_SENSITIVITY',
    weight: 0.2,
    score: maxTlpScore,
    reason: `Most restrictive TLP classification in event cluster`
  });

  // Factor 4: Event volume / velocity
  let volumeScore = 30;
  if (events.length >= 10) volumeScore = 95;
  else if (events.length >= 5) volumeScore = 80;
  else if (events.length >= 3) volumeScore = 65;
  else if (events.length >= 2) volumeScore = 50;
  factors.push({
    factor: 'EVENT_VOLUME',
    weight: 0.15,
    score: volumeScore,
    reason: `${events.length} correlated event(s) in this incident`
  });

  // Factor 5: Confidence score integration (higher confidence = higher priority)
  factors.push({
    factor: 'CONFIDENCE_INTEGRATION',
    weight: 0.1,
    score: incident.confidenceScore || 50,
    reason: `Current incident confidence score: ${incident.confidenceScore || 50}`
  });

  // Weighted total
  const totalWeight = factors.reduce((sum, f) => sum + f.weight, 0);
  const weightedScore = factors.reduce((sum, f) => sum + f.weight * f.score, 0) / totalWeight;
  const finalScore = Math.round(Math.min(100, Math.max(0, weightedScore)));

  return { score: finalScore, factors };
};

// Apply both scoring engines to an incident and persist
const scoreIncident = async (incidentId) => {
  const incident = await Incident.findById(incidentId);
  if (!incident) throw new Error(`Incident not found: ${incidentId}`);

  const confidence = await computeConfidenceScore(incident);
  incident.confidenceScore = confidence.score;
  incident.confidenceFactors = confidence.factors;

  const priority = await computePriorityScore(incident);
  incident.priorityScore = priority.score;
  incident.priorityFactors = priority.factors;

  await incident.save();
  return incident;
};

module.exports = {
  computeConfidenceScore,
  computePriorityScore,
  scoreIncident
};
