const { v4: uuidv4 } = require('uuid');
const RawEvent = require('../models/RawEvent');
const NormalizedEvent = require('../models/NormalizedEvent');
const QuarantineEvent = require('../models/QuarantineEvent');

// Map numeric / text severity into standard enum: LOW, MEDIUM, HIGH, CRITICAL
const mapSeverity = (val) => {
  if (!val) return 'MEDIUM';
  if (typeof val === 'number') {
    if (val >= 4) return 'CRITICAL';
    if (val === 3) return 'HIGH';
    if (val === 2) return 'MEDIUM';
    return 'LOW';
  }
  const s = String(val).toUpperCase();
  if (['CRITICAL', 'FATAL', 'EMERGENCY'].includes(s)) return 'CRITICAL';
  if (['HIGH', 'MAJOR', 'ERROR'].includes(s)) return 'HIGH';
  if (['MEDIUM', 'WARN', 'WARNING'].includes(s)) return 'MEDIUM';
  if (['LOW', 'INFO', 'DEBUG'].includes(s)) return 'LOW';
  return 'MEDIUM';
};

// Map TLP strings into standard enum: CLEAR, GREEN, AMBER, AMBER_STRICT, RED
const mapTlp = (val) => {
  if (!val) return 'AMBER'; // Standard SOC default per US-CERT TLP v2.0
  const clean = String(val).toUpperCase().replace('TLP:', '').trim();
  if (['CLEAR', 'WHITE'].includes(clean)) return 'CLEAR';
  if (clean === 'GREEN') return 'GREEN';
  if (['AMBER+STRICT', 'AMBER_STRICT'].includes(clean)) return 'AMBER_STRICT';
  if (clean === 'AMBER') return 'AMBER';
  if (clean === 'RED') return 'RED';
  return 'AMBER';
};

// Source-specific normalizer functions
const normalizers = {
  crowdstrike: (payload, rawEventId) => {
    return {
      eventId: payload.event_id || `cs-${uuidv4()}`,
      rawEventRef: rawEventId,
      source: 'crowdstrike',
      timestamp: payload.timestamp ? new Date(payload.timestamp) : new Date(),
      eventType: 'endpoint_detection',
      sourceIp: payload.local_ip || payload.host_ip || null,
      destinationIp: payload.remote_ip || null,
      domain: payload.domain || null,
      fileHash: payload.sha256 || payload.md5 || null,
      user: payload.user_name || payload.UserName || null,
      processName: payload.process_name || payload.filename || null,
      severity: mapSeverity(payload.severity),
      tlp: mapTlp(payload.tlp || 'AMBER'),
      confidence: typeof payload.confidence === 'number' ? payload.confidence : 85,
      rawAttributes: {
        computerName: payload.computer_name,
        detectDescription: payload.detect_description,
        tactic: payload.tactic,
        technique: payload.technique
      }
    };
  },

  suricata: (payload, rawEventId) => {
    return {
      eventId: payload.event_id || `suricata-${uuidv4()}`,
      rawEventRef: rawEventId,
      source: 'suricata',
      timestamp: payload.timestamp ? new Date(payload.timestamp) : new Date(),
      eventType: 'network_flow',
      sourceIp: payload.src_ip || null,
      destinationIp: payload.dest_ip || null,
      domain: payload.http?.hostname || payload.dns?.rrname || null,
      fileHash: payload.fileinfo?.sha256 || null,
      user: payload.user || null,
      processName: null,
      severity: mapSeverity(payload.alert?.severity === 1 ? 'CRITICAL' : payload.alert?.severity === 2 ? 'HIGH' : 'MEDIUM'),
      tlp: mapTlp(payload.tlp || 'GREEN'),
      confidence: 80,
      rawAttributes: {
        signature: payload.alert?.signature,
        category: payload.alert?.category,
        proto: payload.proto,
        srcPort: payload.src_port,
        destPort: payload.dest_port
      }
    };
  },

  splunkevent: (payload, rawEventId) => {
    const res = payload.result || payload;
    return {
      eventId: res.event_id || `splunk-${uuidv4()}`,
      rawEventRef: rawEventId,
      source: 'splunkevent',
      timestamp: res._time ? new Date(res._time) : new Date(),
      eventType: res.event_type || 'auth_audit',
      sourceIp: res.src_ip || res.src || null,
      destinationIp: res.dest_ip || res.dest || null,
      domain: res.domain || null,
      fileHash: res.file_hash || res.hash || null,
      user: res.user || res.username || null,
      processName: res.process || res.process_name || null,
      severity: mapSeverity(res.severity),
      tlp: mapTlp(res.tlp || 'AMBER'),
      confidence: 75,
      rawAttributes: {
        rawLog: res._raw,
        sourcetype: res.sourcetype
      }
    };
  },

  generic_webhook: (payload, rawEventId) => {
    return {
      eventId: payload.eventId || payload.id || `gen-${uuidv4()}`,
      rawEventRef: rawEventId,
      source: 'generic_webhook',
      timestamp: payload.timestamp ? new Date(payload.timestamp) : new Date(),
      eventType: payload.eventType || payload.type || 'generic_telemetry',
      sourceIp: payload.sourceIp || payload.srcIp || payload.ip || null,
      destinationIp: payload.destinationIp || payload.destIp || null,
      domain: payload.domain || null,
      fileHash: payload.fileHash || payload.hash || null,
      user: payload.user || payload.username || null,
      processName: payload.processName || payload.process || null,
      severity: mapSeverity(payload.severity),
      tlp: mapTlp(payload.tlp || 'AMBER'),
      confidence: typeof payload.confidence === 'number' ? payload.confidence : 70,
      rawAttributes: payload.rawAttributes || {}
    };
  }
};

const normalizeRawEvent = async (rawEvent) => {
  const normalizer = normalizers[rawEvent.sourceType];
  if (!normalizer) {
    // Quarantine unknown normalizer
    await QuarantineEvent.create({
      rawEventRef: rawEvent._id,
      sourceType: rawEvent.sourceType,
      rawPayload: rawEvent.payload,
      reason: `No normalizer available for sourceType: ${rawEvent.sourceType}`,
      validationErrors: [{ path: 'sourceType', message: 'No registered normalizer' }]
    });
    rawEvent.status = 'QUARANTINED';
    await rawEvent.save();
    return null;
  }

  try {
    const normalizedData = normalizer(rawEvent.payload, rawEvent._id);
    const normalizedEvent = await NormalizedEvent.create(normalizedData);
    
    rawEvent.status = 'PROCESSED';
    await rawEvent.save();

    return normalizedEvent;
  } catch (err) {
    // Quarantine if schema translation breaks
    await QuarantineEvent.create({
      rawEventRef: rawEvent._id,
      sourceType: rawEvent.sourceType,
      rawPayload: rawEvent.payload,
      reason: `Normalization error: ${err.message}`,
      validationErrors: [{ path: 'normalization', message: err.message }]
    });
    rawEvent.status = 'QUARANTINED';
    await rawEvent.save();
    return null;
  }
};

const processPendingRawEvents = async (limit = 100) => {
  const pending = await RawEvent.find({ status: 'RECEIVED' }).limit(limit);
  const results = [];
  for (const raw of pending) {
    const norm = await normalizeRawEvent(raw);
    if (norm) results.push(norm);
  }
  return results;
};

module.exports = {
  normalizers,
  normalizeRawEvent,
  processPendingRawEvents,
  mapSeverity,
  mapTlp
};
