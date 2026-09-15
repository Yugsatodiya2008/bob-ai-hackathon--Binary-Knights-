const crypto = require('crypto');
const Incident = require('../models/Incident');
const NormalizedEvent = require('../models/NormalizedEvent');

const CORRELATION_WINDOW_HOURS = 24;

// Helper to determine maximum severity
const maxSeverity = (severities) => {
  const ranks = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
  let highest = 'LOW';
  for (const s of severities) {
    if ((ranks[s] || 1) > (ranks[highest] || 1)) {
      highest = s;
    }
  }
  return highest;
};

// Helper to determine TLP of an incident (most restrictive TLP wins per US-CERT)
const maxTlp = (tlps) => {
  const tlpRanks = { RED: 5, AMBER_STRICT: 4, AMBER: 3, GREEN: 2, CLEAR: 1 };
  let highest = 'CLEAR';
  for (const t of tlps) {
    if ((tlpRanks[t] || 1) > (tlpRanks[highest] || 1)) {
      highest = t;
    }
  }
  return highest;
};

const generateIncidentId = () => {
  const randomSuffix = crypto.randomBytes(3).toString('hex').toUpperCase();
  const year = new Date().getFullYear();
  return `INC-${year}-${randomSuffix}`;
};

const correlateEvent = async (normalizedEvent) => {
  const cutoffTime = new Date(normalizedEvent.timestamp.getTime() - CORRELATION_WINDOW_HOURS * 60 * 60 * 1000);

  // Search for an active incident that contains events sharing:
  // 1. Same destinationIp (e.g. C2 or external target)
  // 2. Same fileHash (e.g. identical payload)
  // 3. Same sourceIp or user
  const matchingConditions = [];
  if (normalizedEvent.destinationIp) matchingConditions.push({ destinationIp: normalizedEvent.destinationIp });
  if (normalizedEvent.fileHash) matchingConditions.push({ fileHash: normalizedEvent.fileHash });
  if (normalizedEvent.sourceIp) matchingConditions.push({ sourceIp: normalizedEvent.sourceIp });
  if (normalizedEvent.domain) matchingConditions.push({ domain: normalizedEvent.domain });

  let targetIncident = null;

  if (matchingConditions.length > 0) {
    // Find prior normalized events sharing these IOCs within the window
    const relatedEvents = await NormalizedEvent.find({
      _id: { $ne: normalizedEvent._id },
      timestamp: { $gte: cutoffTime },
      $or: matchingConditions
    }).select('_id');

    if (relatedEvents.length > 0) {
      const relatedIds = relatedEvents.map(e => e._id);
      targetIncident = await Incident.findOne({
        status: { $in: ['OPEN', 'IN_TRIAGE'] },
        eventRefs: { $in: relatedIds }
      });
    }
  }

  if (targetIncident) {
    // Correlate into existing incident if not already included
    if (!targetIncident.eventRefs.some(ref => ref.toString() === normalizedEvent._id.toString())) {
      targetIncident.eventRefs.push(normalizedEvent._id);
      
      // Update severity and TLP if incoming event is higher
      const allEvents = await NormalizedEvent.find({ _id: { $in: targetIncident.eventRefs } });
      targetIncident.severity = maxSeverity(allEvents.map(e => e.severity));
      targetIncident.tlp = maxTlp(allEvents.map(e => e.tlp));
      await targetIncident.save();
    }
    return { incident: targetIncident, createdNew: false };
  }

  // Create a brand new incident
  const title = normalizedEvent.rawAttributes?.signature ||
    normalizedEvent.rawAttributes?.detectDescription ||
    `${normalizedEvent.eventType} on ${normalizedEvent.sourceIp || normalizedEvent.user || 'Unknown Target'}`;

  const newIncident = await Incident.create({
    incidentId: generateIncidentId(),
    title: `Threat Alert: ${title}`,
    description: `Correlated security incident automatically assembled from ${normalizedEvent.source} event ${normalizedEvent.eventId}.`,
    severity: normalizedEvent.severity,
    status: 'OPEN',
    tlp: normalizedEvent.tlp,
    confidenceScore: normalizedEvent.confidence || 60,
    confidenceFactors: [{
      factor: 'INITIAL_INGESTION_FIDELITY',
      weight: 1.0,
      score: normalizedEvent.confidence || 60,
      reason: `Base confidence from source connector: ${normalizedEvent.source}`
    }],
    priorityScore: normalizedEvent.severity === 'CRITICAL' ? 85 : normalizedEvent.severity === 'HIGH' ? 70 : 50,
    priorityFactors: [{
      factor: 'SEVERITY_BASELINE',
      weight: 1.0,
      score: normalizedEvent.severity === 'CRITICAL' ? 85 : normalizedEvent.severity === 'HIGH' ? 70 : 50,
      reason: `Initial severity level ${normalizedEvent.severity} reported by ${normalizedEvent.source}`
    }],
    mitreAttack: [],
    eventRefs: [normalizedEvent._id]
  });

  return { incident: newIncident, createdNew: true };
};

const correlateAllUncorrelatedEvents = async () => {
  // Find all normalized events not yet referenced in any incident
  const incidents = await Incident.find().select('eventRefs');
  const alreadyReferenced = new Set();
  incidents.forEach(inc => {
    inc.eventRefs.forEach(id => alreadyReferenced.add(id.toString()));
  });

  const allEvents = await NormalizedEvent.find().sort({ timestamp: 1 });
  const uncorrelated = allEvents.filter(e => !alreadyReferenced.has(e._id.toString()));

  const results = [];
  for (const ev of uncorrelated) {
    const res = await correlateEvent(ev);
    results.push(res);
  }
  return results;
};

module.exports = {
  correlateEvent,
  correlateAllUncorrelatedEvents,
  maxSeverity,
  maxTlp,
  generateIncidentId
};
