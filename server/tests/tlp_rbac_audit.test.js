const request = require('supertest');
const mongoose = require('mongoose');
const { connectDB, disconnectDB } = require('../src/config/db');
const app = require('../src/app');
const Incident = require('../src/models/Incident');
const QuarantineEvent = require('../src/models/QuarantineEvent');
const AuditLog = require('../src/models/AuditLog');

describe('TLP / RBAC Query Enforcement & Audit Logging Tests (§0 #1, #4, FR-11, FR-12)', () => {
  beforeAll(async () => {
    await connectDB();
  });

  afterAll(async () => {
    await disconnectDB();
  });

  beforeEach(async () => {
    await Incident.deleteMany({});
    await QuarantineEvent.deleteMany({});
    await AuditLog.deleteMany({});
  });

  describe('1. Query-Layer TLP Redaction (§0 #4, FR-12.1, FR-12.2)', () => {
    it('strictly filters out incidents exceeding analyst clearance at query-layer', async () => {
      // Seed incidents across multiple TLP classifications
      await Incident.create([
        {
          incidentId: 'INC-TLP-GREEN',
          title: 'Unclassified Scan',
          severity: 'LOW',
          status: 'OPEN',
          tlp: 'GREEN',
          confidenceScore: 70,
          confidenceFactors: [{ factor: 'Test', weight: 1, score: 70, reason: 'test' }],
          priorityScore: 30,
          priorityFactors: [{ factor: 'Test', weight: 1, score: 30, reason: 'test' }]
        },
        {
          incidentId: 'INC-TLP-AMBER',
          title: 'Internal Credential Dump',
          severity: 'HIGH',
          status: 'OPEN',
          tlp: 'AMBER',
          confidenceScore: 85,
          confidenceFactors: [{ factor: 'Test', weight: 1, score: 85, reason: 'test' }],
          priorityScore: 75,
          priorityFactors: [{ factor: 'Test', weight: 1, score: 75, reason: 'test' }]
        },
        {
          incidentId: 'INC-TLP-RED',
          title: 'Critical Covert Nation-State Implant',
          severity: 'CRITICAL',
          status: 'OPEN',
          tlp: 'RED',
          confidenceScore: 95,
          confidenceFactors: [{ factor: 'Test', weight: 1, score: 95, reason: 'test' }],
          priorityScore: 98,
          priorityFactors: [{ factor: 'Test', weight: 1, score: 98, reason: 'test' }]
        }
      ]);

      // Analyst with GREEN clearance queries triage queue
      const greenRes = await request(app)
        .get('/api/v1/incidents/triage')
        .set('x-user-role', 'ANALYST')
        .set('x-user-clearance', 'GREEN');

      expect(greenRes.status).toBe(200);
      expect(greenRes.body.count).toBe(1);
      expect(greenRes.body.data[0].incidentId).toBe('INC-TLP-GREEN');
      // Verify AMBER and RED are completely absent from query response
      const ids = greenRes.body.data.map(i => i.incidentId);
      expect(ids).not.toContain('INC-TLP-AMBER');
      expect(ids).not.toContain('INC-TLP-RED');

      // Analyst with AMBER clearance queries triage queue
      const amberRes = await request(app)
        .get('/api/v1/incidents/triage')
        .set('x-user-role', 'ANALYST')
        .set('x-user-clearance', 'AMBER');

      expect(amberRes.status).toBe(200);
      expect(amberRes.body.count).toBe(2);
      const amberIds = amberRes.body.data.map(i => i.incidentId);
      expect(amberIds).toContain('INC-TLP-GREEN');
      expect(amberIds).toContain('INC-TLP-AMBER');
      expect(amberIds).not.toContain('INC-TLP-RED');

      // Commander with RED clearance queries triage queue
      const redRes = await request(app)
        .get('/api/v1/incidents/triage')
        .set('x-user-role', 'COMMANDER')
        .set('x-user-clearance', 'RED');

      expect(redRes.status).toBe(200);
      expect(redRes.body.count).toBe(3);
    });

    it('rejects direct document lookup when document TLP exceeds user clearance', async () => {
      const redIncident = await Incident.create({
        incidentId: 'INC-SECRET-RED',
        title: 'Top Secret Operation Telemetry',
        severity: 'CRITICAL',
        status: 'OPEN',
        tlp: 'RED',
        confidenceScore: 90,
        confidenceFactors: [{ factor: 'Test', weight: 1, score: 90, reason: 'test' }],
        priorityScore: 95,
        priorityFactors: [{ factor: 'Test', weight: 1, score: 95, reason: 'test' }]
      });

      // User with GREEN clearance attempts direct access
      const forbiddenRes = await request(app)
        .get(`/api/v1/incidents/${redIncident._id}`)
        .set('x-user-role', 'ANALYST')
        .set('x-user-clearance', 'GREEN');

      expect(forbiddenRes.status).toBe(403);
      expect(forbiddenRes.body.success).toBe(false);
      expect(forbiddenRes.body.error).toContain('exceeding user clearance');

      // User with RED clearance attempts direct access
      const allowedRes = await request(app)
        .get(`/api/v1/incidents/${redIncident._id}`)
        .set('x-user-role', 'ANALYST')
        .set('x-user-clearance', 'RED');

      expect(allowedRes.status).toBe(200);
      expect(allowedRes.body.data.incidentId).toBe('INC-SECRET-RED');
    });
  });

  describe('2. Role-Based Access Control (RBAC)', () => {
    it('restricts /api/v1/audit-logs to ADMIN and COMMANDER only', async () => {
      // Attempt as ANALYST
      const analystRes = await request(app)
        .get('/api/v1/audit-logs')
        .set('x-user-role', 'ANALYST');

      expect(analystRes.status).toBe(403);
      expect(analystRes.body.error).toContain('Forbidden');

      // Attempt as COMMANDER
      const commanderRes = await request(app)
        .get('/api/v1/audit-logs')
        .set('x-user-role', 'COMMANDER');

      expect(commanderRes.status).toBe(200);
      expect(commanderRes.body.success).toBe(true);

      // Attempt as ADMIN
      const adminRes = await request(app)
        .get('/api/v1/audit-logs')
        .set('x-user-role', 'ADMIN');

      expect(adminRes.status).toBe(200);
    });
  });

  describe('3. Human-in-the-Loop Closure & Immutable Audit Logging (§0 #1, FR-11.1)', () => {
    it('blocks closure without sign-off and writes immutable audit log upon valid closure', async () => {
      const incident = await Incident.create({
        incidentId: 'INC-CLOSE-TEST',
        title: 'Ransomware Outbreak',
        severity: 'CRITICAL',
        status: 'OPEN',
        tlp: 'AMBER',
        confidenceScore: 92,
        confidenceFactors: [{ factor: 'Test', weight: 1, score: 92, reason: 'test' }],
        priorityScore: 99,
        priorityFactors: [{ factor: 'Test', weight: 1, score: 99, reason: 'test' }]
      });

      // 1. Attempt autonomous / unsigned closure
      const badClose = await request(app)
        .patch(`/api/v1/incidents/${incident._id}/status`)
        .set('x-user-role', 'ANALYST')
        .set('x-user-clearance', 'AMBER')
        .send({
          status: 'CLOSED'
        });

      expect(badClose.status).toBe(403);
      expect(badClose.body.error).toContain('§0 Constraint Violation');

      // 2. Perform signed human closure with explicit rationale
      const validClose = await request(app)
        .patch(`/api/v1/incidents/${incident._id}/status`)
        .set('x-user-role', 'ANALYST')
        .set('x-user-clearance', 'AMBER')
        .set('x-user-id', 'analyst-jane-doe')
        .send({
          status: 'CLOSED',
          analystName: 'Jane Doe',
          rationale: 'Host isolated, persistence eradicated, verified benign.',
          signOffConfirmed: true
        });

      expect(validClose.status).toBe(200);
      expect(validClose.body.data.status).toBe('CLOSED');
      expect(validClose.body.data.closureMetadata.signOffConfirmed).toBe(true);
      expect(validClose.body.data.closureMetadata.closedBy).toBe('Jane Doe');

      // 3. Verify immutable audit log creation
      const logs = await AuditLog.find({ resourceId: 'INC-CLOSE-TEST' });
      expect(logs.length).toBe(1);
      expect(logs[0].action).toBe('INCIDENT_STATUS_CHANGE');
      expect(logs[0].role).toBe('ANALYST');
      expect(logs[0].details.newStatus).toBe('CLOSED');
      expect(logs[0].details.rationale).toBe('Host isolated, persistence eradicated, verified benign.');
    });
  });

  describe('4. Quarantine Management & Audit Trail (FR-2.4, §0 #3)', () => {
    it('lists quarantine records and audits analyst review actions', async () => {
      const qEvent = await QuarantineEvent.create({
        sourceType: 'unknown_siem',
        rawPayload: { corrupted: true },
        reason: 'Unsupported source type',
        status: 'QUARANTINED'
      });

      // List quarantine
      const listRes = await request(app).get('/api/v1/quarantine');
      expect(listRes.status).toBe(200);
      expect(listRes.body.count).toBe(1);

      // Review quarantine record
      const reviewRes = await request(app)
        .patch(`/api/v1/quarantine/${qEvent._id}/review`)
        .set('x-user-role', 'ANALYST')
        .set('x-user-id', 'analyst-bob')
        .set('x-user-email', 'bob@sentineliq.internal')
        .send({
          status: 'RESOLVED',
          notes: 'Identified as experimental legacy sensor. Added parser to backlog.'
        });

      expect(reviewRes.status).toBe(200);
      expect(reviewRes.body.data.status).toBe('RESOLVED');

      // Verify audit log recorded
      const qAudit = await AuditLog.findOne({
        action: 'QUARANTINE_REVIEWED',
        resourceId: qEvent._id.toString()
      });
      expect(qAudit).not.toBeNull();
      expect(qAudit.details.newStatus).toBe('RESOLVED');
      expect(qAudit.userEmail).toBe('bob@sentineliq.internal');
    });
  });
});
