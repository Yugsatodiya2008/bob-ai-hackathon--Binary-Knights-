const request = require('supertest');
const mongoose = require('mongoose');
const { connectDB, disconnectDB } = require('../src/config/db');
const app = require('../src/app');
const RawEvent = require('../src/models/RawEvent');
const NormalizedEvent = require('../src/models/NormalizedEvent');
const Incident = require('../src/models/Incident');
const BlufReport = require('../src/models/BlufReport');
const QuarantineEvent = require('../src/models/QuarantineEvent');
const AuditLog = require('../src/models/AuditLog');

describe('FR-7.1/FR-7.2/FR-7.3 BLUF Traceability & Approval (§0 #5 Traceable Claims)', () => {
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
    await BlufReport.deleteMany({});
    await QuarantineEvent.deleteMany({});
    await AuditLog.deleteMany({});
  });

  test('§0 CRITICAL: Every BLUF finding has non-empty supportingEvidenceRefs pointing to real normalized_events', async () => {
    // Build full pipeline
    await request(app).post('/api/v1/ingest/crowdstrike').send({
      event_id: 'CS-BLUF-01', severity: 4, local_ip: '10.0.0.10',
      user_name: 'SYSTEM', filename: 'mimikatz.exe',
      detect_description: 'LSASS credential dump detected'
    });
    await request(app).post('/api/v1/ingest/suricata').send({
      event_id: 'SURI-BLUF-01', src_ip: '10.0.0.10', dest_ip: '198.51.100.5',
      alert: { signature: 'ET MALWARE C2 Beacon', severity: 1 }
    });
    await request(app).post('/api/v1/pipeline/run');

    const incident = await Incident.findOne();
    const blufRes = await request(app)
      .post(`/api/v1/incidents/${incident._id}/bluf/generate`)
      .send({ analystName: 'SSgt Chen' });

    expect(blufRes.status).toBe(201);
    const report = blufRes.body.data;

    // Every finding MUST have at least 1 evidence ref
    for (const finding of report.keyFindings) {
      expect(finding.supportingEvidenceRefs.length).toBeGreaterThan(0);
      // Verify each ref is a real normalized_event ID
      for (const ref of finding.supportingEvidenceRefs) {
        const exists = await NormalizedEvent.findById(ref);
        expect(exists).not.toBeNull();
      }
    }
  });

  test('BLUF approval workflow: DRAFT → APPROVED → LOCKED with human sign-off', async () => {
    await request(app).post('/api/v1/ingest/crowdstrike').send({
      event_id: 'CS-APPROVE-01', severity: 3, detect_description: 'Suspicious activity'
    });
    await request(app).post('/api/v1/pipeline/run');

    const incident = await Incident.findOne();
    const blufRes = await request(app)
      .post(`/api/v1/incidents/${incident._id}/bluf/generate`)
      .send({ analystName: 'Analyst Zhang' });

    const reportId = blufRes.body.data.reportId;
    expect(blufRes.body.data.status).toBe('DRAFT');

    // Approve without analyst name → must fail
    const noNameApproval = await request(app)
      .post(`/api/v1/bluf/${reportId}/approve`)
      .send({});
    expect(noNameApproval.status).toBe(400);

    // Approve with analyst name
    const approveRes = await request(app)
      .post(`/api/v1/bluf/${reportId}/approve`)
      .send({ analystName: 'Cdr Morrison' });
    expect(approveRes.status).toBe(200);
    expect(approveRes.body.data.status).toBe('APPROVED');

    // Lock the report
    const lockRes = await request(app)
      .post(`/api/v1/bluf/${reportId}/lock`)
      .send({ analystName: 'Cdr Morrison' });
    expect(lockRes.status).toBe(200);
    expect(lockRes.body.data.status).toBe('LOCKED');

    // Verify audit trail
    const audits = await AuditLog.find({ resourceType: 'BLUF_REPORT' });
    expect(audits.length).toBeGreaterThanOrEqual(3); // generated + approved + locked
  });
});
