const request = require('supertest');
const mongoose = require('mongoose');
const { connectDB, disconnectDB } = require('../src/config/db');
const app = require('../src/app');
const RawEvent = require('../src/models/RawEvent');
const NormalizedEvent = require('../src/models/NormalizedEvent');
const QuarantineEvent = require('../src/models/QuarantineEvent');
const { normalizeRawEvent } = require('../src/services/normalizationService');

describe('FR-2.1 Normalization Worker & ECS Standardization', () => {
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
    await QuarantineEvent.deleteMany({});
  });

  test('Normalizes CrowdStrike detection to standard ECS format', async () => {
    const raw = await RawEvent.create({
      sourceType: 'crowdstrike',
      payload: {
        event_id: 'CS-EVENT-100',
        computer_name: 'DC-PRIMARY-01',
        user_name: 'SYSTEM',
        filename: 'mimikatz.exe',
        sha256: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
        detect_description: 'LSASS memory injection detected',
        severity: 4,
        tlp: 'TLP:AMBER+STRICT'
      },
      payloadHash: 'hash-cs-100',
      status: 'RECEIVED'
    });

    const norm = await normalizeRawEvent(raw);
    expect(norm).not.toBeNull();
    expect(norm.eventId).toBe('CS-EVENT-100');
    expect(norm.source).toBe('crowdstrike');
    expect(norm.processName).toBe('mimikatz.exe');
    expect(norm.user).toBe('SYSTEM');
    expect(norm.severity).toBe('CRITICAL');
    expect(norm.tlp).toBe('AMBER_STRICT');
    expect(norm.fileHash).toBe('5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8');

    const updatedRaw = await RawEvent.findById(raw._id);
    expect(updatedRaw.status).toBe('PROCESSED');
  });

  test('Normalizes Suricata alert with network IPs and protocol', async () => {
    const raw = await RawEvent.create({
      sourceType: 'suricata',
      payload: {
        event_id: 'SURI-NET-200',
        alert: { signature: 'ET MALWARE Cobalt Strike Beacon', severity: 1 },
        src_ip: '10.0.0.45',
        dest_ip: '185.220.101.5',
        proto: 'TCP',
        src_port: 49210,
        dest_port: 443,
        tlp: 'TLP:GREEN'
      },
      payloadHash: 'hash-suri-200',
      status: 'RECEIVED'
    });

    const norm = await normalizeRawEvent(raw);
    expect(norm).not.toBeNull();
    expect(norm.sourceIp).toBe('10.0.0.45');
    expect(norm.destinationIp).toBe('185.220.101.5');
    expect(norm.severity).toBe('CRITICAL');
    expect(norm.tlp).toBe('GREEN');
    expect(norm.rawAttributes.signature).toBe('ET MALWARE Cobalt Strike Beacon');
  });

  test('Batch processing endpoint normalizes multiple pending events', async () => {
    // Ingest 2 raw events
    await request(app).post('/api/v1/ingest/crowdstrike').send({ event_id: 'CS-1', filename: 'cmd.exe', severity: 2 });
    await request(app).post('/api/v1/ingest/suricata').send({ event_id: 'SURI-1', src_ip: '10.0.0.1', alert: { severity: 2 } });

    const batchRes = await request(app).post('/api/v1/normalize/batch');
    expect(batchRes.status).toBe(200);
    expect(batchRes.body.processedCount).toBe(2);

    const normCount = await NormalizedEvent.countDocuments();
    expect(normCount).toBe(2);
  });
});
