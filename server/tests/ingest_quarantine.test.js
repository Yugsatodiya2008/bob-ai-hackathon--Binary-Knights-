const request = require('supertest');
const mongoose = require('mongoose');
const { connectDB, disconnectDB } = require('../src/config/db');
const app = require('../src/app');
const RawEvent = require('../src/models/RawEvent');
const QuarantineEvent = require('../src/models/QuarantineEvent');

describe('FR-1.1 Ingestion & FR-2.4 Quarantine Guard (§0 No Silent Data Loss)', () => {
  beforeAll(async () => {
    process.env.NODE_ENV = 'test';
    await connectDB();
  });

  afterAll(async () => {
    await disconnectDB();
  });

  beforeEach(async () => {
    await RawEvent.deleteMany({});
    await QuarantineEvent.deleteMany({});
  });

  test('Happy path: Ingests valid CrowdStrike alert to raw_events with SHA-256 hash', async () => {
    const payload = {
      event_id: 'CS-ALERT-001',
      computer_name: 'FINANCE-WS-09',
      detect_description: 'Suspicious PowerShell execution bypassing execution policy',
      severity: 4
    };

    const res = await request(app)
      .post('/api/v1/ingest/crowdstrike')
      .send(payload)
      .set('Content-Type', 'application/json');

    expect(res.status).toBe(201);
    expect(res.body.success).toBe(true);
    expect(res.body.data.status).toBe('SUCCESS');
    expect(res.body.data.payloadHash).toBeDefined();

    const rawInDb = await RawEvent.findById(res.body.data.rawEventId);
    expect(rawInDb).not.toBeNull();
    expect(rawInDb.sourceType).toBe('crowdstrike');
    expect(rawInDb.payload.event_id).toBe('CS-ALERT-001');
  });

  test('Happy path: Ingests Suricata alert', async () => {
    const payload = {
      timestamp: '2026-09-15T12:00:00.000Z',
      alert: { signature: 'ET MALWARE CobaltStrike Beacon Observed', severity: 1 },
      src_ip: '192.168.1.50',
      dest_ip: '198.51.100.22'
    };

    const res = await request(app)
      .post('/api/v1/ingest/suricata')
      .send(payload);

    expect(res.status).toBe(201);
    expect(res.body.success).toBe(true);
  });

  test('Malformed input: Unsupported source type routes to quarantine', async () => {
    const res = await request(app)
      .post('/api/v1/ingest/unknown_tool_xyz')
      .send({ some: 'data' });

    expect(res.status).toBe(422);
    expect(res.body.data.status).toBe('QUARANTINED');

    const quarantined = await QuarantineEvent.findById(res.body.data.quarantineId);
    expect(quarantined).not.toBeNull();
    expect(quarantined.reason).toContain('Unsupported source type');
  });

  test('Malformed input: Empty payload routes to quarantine', async () => {
    const res = await request(app)
      .post('/api/v1/ingest/crowdstrike')
      .send({});

    expect(res.status).toBe(422);
    expect(res.body.data.status).toBe('QUARANTINED');

    const quarantined = await QuarantineEvent.findById(res.body.data.quarantineId);
    expect(quarantined).not.toBeNull();
    expect(quarantined.reason).toContain('Empty or malformed payload');
  });

  test('CRITICAL §0: Zero Silent Drop Guarantee — all events persist to either raw_events or quarantine_events', async () => {
    const testCases = [
      { source: 'crowdstrike', body: { valid: true, id: 1 } },
      { source: 'suricata', body: { alert: 'test' } },
      { source: 'splunkevent', body: { result: 'log entry' } },
      { source: 'generic_webhook', body: { metric: 'high' } },
      { source: 'bad_source', body: { foo: 'bar' } },
      { source: 'crowdstrike', body: {} }
    ];

    for (const tc of testCases) {
      await request(app)
        .post(`/api/v1/ingest/${tc.source}`)
        .send(tc.body);
    }

    const rawCount = await RawEvent.countDocuments();
    const quarantineCount = await QuarantineEvent.countDocuments();
    const totalPersisted = rawCount + quarantineCount;

    // Total persisted MUST equal total events sent (6) — absolute zero data loss
    expect(totalPersisted).toBe(testCases.length);
    expect(rawCount).toBe(4);
    expect(quarantineCount).toBe(2);
  });
});
