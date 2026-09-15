const request = require('supertest');
const mongoose = require('mongoose');
const { connectDB, disconnectDB } = require('../src/config/db');
const app = require('../src/app');
const RawEvent = require('../src/models/RawEvent');
const NormalizedEvent = require('../src/models/NormalizedEvent');
const Incident = require('../src/models/Incident');
const AuditLog = require('../src/models/AuditLog');
const QuarantineEvent = require('../src/models/QuarantineEvent');

describe('FR-3.1/FR-3.2 Correlation & Dedup + §0 Human-in-the-Loop Closure', () => {
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
    await AuditLog.deleteMany({});
    await QuarantineEvent.deleteMany({});
  });

  test('Creates a new incident from a single uncorrelated event', async () => {
    // Ingest → Normalize → Correlate
    await request(app).post('/api/v1/ingest/crowdstrike').send({
      event_id: 'CS-CORR-01',
      computer_name: 'DC-01',
      user_name: 'admin',
      severity: 4,
      local_ip: '10.0.0.10',
      detect_description: 'LSASS credential dump detected'
    });
    await request(app).post('/api/v1/normalize/batch');

    const corrRes = await request(app).post('/api/v1/correlate');
    expect(corrRes.status).toBe(200);
    expect(corrRes.body.newIncidents).toBe(1);

    const incidents = await Incident.find();
    expect(incidents.length).toBe(1);
    expect(incidents[0].confidenceFactors.length).toBeGreaterThan(0);
    expect(incidents[0].priorityFactors.length).toBeGreaterThan(0);
  });

  test('Correlates two events sharing the same sourceIp into a single incident', async () => {
    // Two events from same IP within 24h should merge
    await request(app).post('/api/v1/ingest/crowdstrike').send({
      event_id: 'CS-IP-01', local_ip: '192.168.1.50', severity: 3, detect_description: 'Suspicious PS execution'
    });
    await request(app).post('/api/v1/ingest/suricata').send({
      event_id: 'SURI-IP-01', src_ip: '192.168.1.50', dest_ip: '198.51.100.1', alert: { signature: 'ET TROJAN C2', severity: 1 }
    });
    await request(app).post('/api/v1/normalize/batch');

    const corrRes = await request(app).post('/api/v1/correlate');
    expect(corrRes.status).toBe(200);

    const incidents = await Incident.find();
    // Should be merged into 1 incident (same sourceIp)
    expect(incidents.length).toBe(1);
    expect(incidents[0].eventRefs.length).toBe(2);
  });

  test('§0 CRITICAL: Autonomous incident closure is BLOCKED without analyst sign-off', async () => {
    await request(app).post('/api/v1/ingest/crowdstrike').send({
      event_id: 'CS-CLOSE-01', severity: 4, detect_description: 'Critical alert'
    });
    await request(app).post('/api/v1/normalize/batch');
    await request(app).post('/api/v1/correlate');

    const incident = await Incident.findOne();
    // Attempt to close without sign-off — MUST be rejected
    const closeRes = await request(app)
      .patch(`/api/v1/incidents/${incident._id}/status`)
      .send({ status: 'CLOSED' });

    expect(closeRes.status).toBe(403);
    expect(closeRes.body.error).toContain('§0 Constraint Violation');

    // Now close properly with human sign-off
    const properClose = await request(app)
      .patch(`/api/v1/incidents/${incident._id}/status`)
      .send({
        status: 'CLOSED',
        analystName: 'SGT Rodriguez',
        rationale: 'Confirmed false positive after manual forensic review of LSASS handles',
        signOffConfirmed: true
      });

    expect(properClose.status).toBe(200);
    expect(properClose.body.data.status).toBe('CLOSED');
    expect(properClose.body.data.closureMetadata.signOffConfirmed).toBe(true);

    // Verify audit log was created
    const auditEntry = await AuditLog.findOne({ action: 'INCIDENT_STATUS_CHANGE' });
    expect(auditEntry).not.toBeNull();
    expect(auditEntry.details.rationale).toContain('false positive');
  });
});
