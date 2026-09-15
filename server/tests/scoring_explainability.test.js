const request = require('supertest');
const mongoose = require('mongoose');
const { connectDB, disconnectDB } = require('../src/config/db');
const app = require('../src/app');
const RawEvent = require('../src/models/RawEvent');
const NormalizedEvent = require('../src/models/NormalizedEvent');
const Incident = require('../src/models/Incident');
const QuarantineEvent = require('../src/models/QuarantineEvent');
const AuditLog = require('../src/models/AuditLog');
const { scoreIncident, computeConfidenceScore, computePriorityScore } = require('../src/services/scoringService');

describe('FR-4.1/FR-4.2/FR-6.1/FR-6.2 Explainable Scoring (§0 Explainability Hard Requirement)', () => {
  beforeAll(async () => {
    process.env.NODE_ENV = 'test';
    await connectDB();
  });

  afterAll(async () => {
    await disconnectDB();
  });

  beforeEach(async () => {
    await RawEvent.deleteMany({});
    await NormalizedEvent.deleteMany({});
    await Incident.deleteMany({});
    await QuarantineEvent.deleteMany({});
    await AuditLog.deleteMany({});
  });

  test('Confidence score ALWAYS returns non-empty factors array (§0 #2)', async () => {
    // Create a multi-source incident
    await request(app).post('/api/v1/ingest/crowdstrike').send({
      event_id: 'CS-SCORE-01', severity: 4, local_ip: '10.0.0.10',
      user_name: 'admin', sha256: 'abc123deadbeef', detect_description: 'Credential theft'
    });
    await request(app).post('/api/v1/ingest/suricata').send({
      event_id: 'SURI-SCORE-01', src_ip: '10.0.0.10', dest_ip: '198.51.100.5',
      alert: { signature: 'C2 Beacon', severity: 1 }
    });
    await request(app).post('/api/v1/normalize/batch');
    await request(app).post('/api/v1/correlate');

    const incident = await Incident.findOne();
    const scored = await scoreIncident(incident._id);

    // §0 Hard requirement: score with no factor breakdown is INCOMPLETE
    expect(scored.confidenceFactors).toBeDefined();
    expect(scored.confidenceFactors.length).toBeGreaterThanOrEqual(3);
    expect(scored.confidenceScore).toBeGreaterThan(0);
    expect(scored.confidenceScore).toBeLessThanOrEqual(100);

    // Verify each factor has all required fields
    scored.confidenceFactors.forEach(f => {
      expect(f.factor).toBeTruthy();
      expect(typeof f.weight).toBe('number');
      expect(typeof f.score).toBe('number');
      expect(f.reason).toBeTruthy();
    });
  });

  test('Priority score ALWAYS returns non-empty factors array (§0 #2)', async () => {
    await request(app).post('/api/v1/ingest/crowdstrike').send({
      event_id: 'CS-PRI-01', severity: 4, filename: 'mimikatz.exe', user_name: 'SYSTEM'
    });
    await request(app).post('/api/v1/normalize/batch');
    await request(app).post('/api/v1/correlate');

    const incident = await Incident.findOne();
    const scored = await scoreIncident(incident._id);

    expect(scored.priorityFactors).toBeDefined();
    expect(scored.priorityFactors.length).toBeGreaterThanOrEqual(3);
    expect(scored.priorityScore).toBeGreaterThan(0);

    // Verify structure
    scored.priorityFactors.forEach(f => {
      expect(f.factor).toBeTruthy();
      expect(typeof f.weight).toBe('number');
      expect(typeof f.score).toBe('number');
      expect(f.reason).toBeTruthy();
    });
  });

  test('Multi-source corroboration raises confidence vs single-source', async () => {
    // Single source incident
    await request(app).post('/api/v1/ingest/crowdstrike').send({
      event_id: 'CS-SINGLE', severity: 3, local_ip: '10.0.0.99'
    });
    await request(app).post('/api/v1/normalize/batch');
    await request(app).post('/api/v1/correlate');

    const singleInc = await Incident.findOne();
    const singleScored = await scoreIncident(singleInc._id);
    const singleConf = singleScored.confidenceScore;

    // Clean and create multi-source incident
    await RawEvent.deleteMany({}); await NormalizedEvent.deleteMany({}); await Incident.deleteMany({});

    await request(app).post('/api/v1/ingest/crowdstrike').send({
      event_id: 'CS-MULTI', severity: 3, local_ip: '10.0.0.88'
    });
    await request(app).post('/api/v1/ingest/suricata').send({
      event_id: 'SURI-MULTI', src_ip: '10.0.0.88', alert: { severity: 2 }
    });
    await request(app).post('/api/v1/normalize/batch');
    await request(app).post('/api/v1/correlate');

    const multiInc = await Incident.findOne();
    const multiScored = await scoreIncident(multiInc._id);

    expect(multiScored.confidenceScore).toBeGreaterThan(singleConf);
  });
});
