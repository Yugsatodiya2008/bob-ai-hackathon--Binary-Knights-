const mongoose = require('mongoose');
const { connectDB, disconnectDB } = require('../src/config/db');
const RawEvent = require('../src/models/RawEvent');
const QuarantineEvent = require('../src/models/QuarantineEvent');
const NormalizedEvent = require('../src/models/NormalizedEvent');
const Incident = require('../src/models/Incident');
const BlufReport = require('../src/models/BlufReport');
const AuditLog = require('../src/models/AuditLog');

describe('Database Models & Schemas (SRS §6.2)', () => {
  beforeAll(async () => {
    process.env.NODE_ENV = 'test';
    await connectDB();
  });

  afterAll(async () => {
    await disconnectDB();
  });

  afterEach(async () => {
    const collections = mongoose.connection.collections;
    for (const key in collections) {
      await collections[key].deleteMany({});
    }
  });

  test('RawEvent schema persists raw payloads and hashes', async () => {
    const raw = await RawEvent.create({
      sourceType: 'crowdstrike',
      payload: { alert_id: 'CS-999', score: 85 },
      headers: { 'user-agent': 'CS-Webhook' },
      payloadHash: 'abc123hash',
      status: 'RECEIVED'
    });
    expect(raw._id).toBeDefined();
    expect(raw.sourceType).toBe('crowdstrike');
  });

  test('QuarantineEvent captures malformed data without silent loss', async () => {
    const q = await QuarantineEvent.create({
      sourceType: 'suricata',
      rawPayload: 'CORRUPTED_NON_JSON_DATA',
      reason: 'JSON parse error',
      validationErrors: [{ path: 'root', message: 'Unexpected token' }]
    });
    expect(q._id).toBeDefined();
    expect(q.status).toBe('QUARANTINED');
  });

  test('Incident requires confidence & priority factor breakdowns', async () => {
    const inc = await Incident.create({
      incidentId: 'INC-2026-TEST',
      title: 'Credential Dumping via LSASS',
      severity: 'HIGH',
      confidenceScore: 92,
      confidenceFactors: [{
        factor: 'MULTI_SOURCE_CORROBORATION',
        weight: 0.5,
        score: 95,
        reason: 'Corroborated by CrowdStrike and Suricata'
      }],
      priorityScore: 88,
      priorityFactors: [{
        factor: 'DOMAIN_CONTROLLER_TARGET',
        weight: 0.6,
        score: 90,
        reason: 'Target asset is primary domain controller'
      }],
      mitreAttack: [{
        tactic: 'Credential Access',
        techniqueId: 'T1003.001',
        techniqueName: 'LSASS Memory',
        confidence: 90,
        factors: ['Process lsass.exe accessed with PROCESS_VM_READ']
      }]
    });
    expect(inc.confidenceFactors.length).toBeGreaterThan(0);
    expect(inc.priorityFactors.length).toBeGreaterThan(0);
    expect(inc.mitreAttack[0].techniqueId).toBe('T1003.001');
  });

  test('BlufReport requires supportingEvidenceRefs for keyFindings', async () => {
    const raw = await RawEvent.create({
      sourceType: 'generic_webhook',
      payload: { id: 1 },
      payloadHash: 'hash1'
    });
    const norm = await NormalizedEvent.create({
      eventId: 'norm-uuid-1',
      rawEventRef: raw._id,
      source: 'generic_webhook',
      timestamp: new Date(),
      eventType: 'auth_failure',
      severity: 'HIGH',
      tlp: 'AMBER'
    });
    const inc = await Incident.create({
      incidentId: 'INC-2026-BLUF',
      title: 'Test Incident',
      confidenceScore: 80,
      confidenceFactors: [{ factor: 'TEST', weight: 1, score: 80, reason: 'test' }],
      priorityScore: 80,
      priorityFactors: [{ factor: 'TEST', weight: 1, score: 80, reason: 'test' }]
    });

    const bluf = await BlufReport.create({
      reportId: 'BLUF-2026-001',
      incidentRef: inc._id,
      executiveSummary: 'Host compromised via brute force',
      keyFindings: [{
        statement: 'Brute force attempts observed from external IP',
        supportingEvidenceRefs: [norm._id]
      }],
      recommendedActions: [{ action: 'Isolate host', priority: 'IMMEDIATE' }]
    });

    expect(bluf.keyFindings[0].supportingEvidenceRefs).toContainEqual(norm._id);
  });
});
