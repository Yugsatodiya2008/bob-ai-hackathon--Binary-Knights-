const RawEvent = require('../models/RawEvent');
const NormalizedEvent = require('../models/NormalizedEvent');
const Incident = require('../models/Incident');
const QuarantineEvent = require('../models/QuarantineEvent');
const BlufReport = require('../models/BlufReport');
const { ingestPayload } = require('./ingestionService');
const { processPendingRawEvents } = require('./normalizationService');
const { correlateAllUncorrelatedEvents } = require('./correlationService');
const { mapIncidentToAttack, generateHeatmapData } = require('./mitreService');
const { scoreIncident } = require('./scoringService');
const { generateBluf, approveBluf } = require('./blufService');
const { recordAudit } = require('../middleware/audit');

async function seedInitialData() {
  const existingIncidents = await Incident.countDocuments();
  if (existingIncidents > 0) {
    console.log(`[SentinelIQ-Seed] Database already populated with ${existingIncidents} incidents. Skipping seed.`);
    return;
  }

  console.log('[SentinelIQ-Seed] Seeding realistic SOC threat telemetry scenarios...');

  // 1. Ingest Multi-stage APT Campaign telemetry
  // 1a. CrowdStrike Endpoint Event: PowerShell Cobalt Strike Loader
  await ingestPayload({
    sourceType: 'crowdstrike',
    rawPayload: {
      event_id: 'CS-SEED-001',
      event_type: 'ProcessRollup2',
      timestamp: new Date(Date.now() - 3600000).toISOString(),
      ComputerName: 'WKSTN-FIN-042',
      LocalIP: '10.0.4.42',
      UserName: 'CORP\\jdoe',
      CommandLine: 'powershell.exe -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAg... -nop -w hidden',
      ImageFileName: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
      MD5HashData: 'd41d8cd98f00b204e9800998ecf8427e',
      SHA256HashData: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
      Severity: 'High',
      TlpLevel: 'AMBER'
    }
  });

  // 1b. Suricata Network Event: External C2 beaconing to 198.51.100.88
  await ingestPayload({
    sourceType: 'suricata',
    rawPayload: {
      timestamp: new Date(Date.now() - 3300000).toISOString(),
      event_type: 'alert',
      src_ip: '10.0.4.42',
      src_port: 49832,
      dest_ip: '198.51.100.88',
      dest_port: 443,
      proto: 'TCP',
      alert: {
        action: 'allowed',
        gid: 1,
        signature_id: 2028491,
        rev: 2,
        signature: 'ET MALWARE Cobalt Strike Beacon Malleable C2 Profile Observed',
        category: 'A Network Trojan was detected',
        severity: 1
      },
      tlp: 'AMBER'
    }
  });

  // 1c. Splunk SIEM Event: Privileged Group Modification
  await ingestPayload({
    sourceType: 'splunkevent',
    rawPayload: {
      event_id: 'SPLUNK-SEED-003',
      time: new Date(Date.now() - 3000000).toISOString(),
      source: 'WinEventLog:Security:4728',
      src_ip: '10.0.4.42',
      dest_ip: '198.51.100.88',
      user: 'CORP\\jdoe',
      action: 'Member Added to Security Enabled Global Group Domain Admins',
      severity: 'High',
      tlp: 'AMBER'
    }
  });

  // 2. Scenario 2: Ransomware Precursor (TLP:RED)
  await ingestPayload({
    sourceType: 'crowdstrike',
    rawPayload: {
      event_id: 'CS-SEED-004',
      event_type: 'DetectionSummaryEvent',
      timestamp: new Date(Date.now() - 1800000).toISOString(),
      ComputerName: 'DC01.INTERNAL',
      LocalIP: '10.0.0.1',
      UserName: 'CORP\\krbtgt',
      CommandLine: 'mimikatz.exe privilege::debug sekurlsa::logonpasswords exit',
      ImageFileName: 'C:\\Temp\\mimikatz.exe',
      MD5HashData: 'e3b0c44298fc1c149afbf4c8996fb924',
      Severity: 'Critical',
      TlpLevel: 'RED'
    }
  });

  // 3. Scenario 3: Routine External Reconnaissance (TLP:GREEN)
  await ingestPayload({
    sourceType: 'suricata',
    rawPayload: {
      timestamp: new Date(Date.now() - 7200000).toISOString(),
      event_type: 'alert',
      src_ip: '203.0.113.15',
      src_port: 54112,
      dest_ip: '10.0.1.10',
      dest_port: 80,
      proto: 'TCP',
      alert: {
        action: 'blocked',
        signature: 'ET SCAN Potential Nmap SYN Scan Detected',
        category: 'Attempted Information Leak',
        severity: 3
      },
      tlp: 'GREEN'
    }
  });

  // 4. Scenario 4: Malformed Legacy Payload (To seed Quarantine Manager)
  await ingestPayload({
    sourceType: 'unsupported_syslog_sensor',
    rawPayload: {
      raw_packet: '<13>Sep 15 12:00:00 legacy-fw kernel: DROP INVALID UDP packet',
      bad_field: 'unparsed'
    }
  });

  // Run pipeline: Normalization -> Correlation -> MITRE ATT&CK -> Explainable Scoring
  console.log('[SentinelIQ-Seed] Running end-to-end pipeline on seeded telemetry...');
  const normalized = await processPendingRawEvents();
  console.log(`[SentinelIQ-Seed] Normalized ${normalized.length} events.`);

  const correlated = await correlateAllUncorrelatedEvents();
  console.log(`[SentinelIQ-Seed] Correlated into ${correlated.length} incidents.`);

  const incidents = await Incident.find({});
  for (const inc of incidents) {
    await mapIncidentToAttack(inc._id);
    await scoreIncident(inc._id);
  }

  // Generate initial BLUF report for the multi-stage campaign incident
  const aptIncident = await Incident.findOne({ title: /APT|Multi-Source|Cobalt Strike/i }) || incidents[0];
  if (aptIncident) {
    const bluf = await generateBluf(aptIncident._id);
    await approveBluf(bluf.reportId, 'Lead Analyst Sarah Vance');
    console.log(`[SentinelIQ-Seed] Generated and approved BLUF report ${bluf.reportId} for incident ${aptIncident.incidentId}`);
  }

  // Record initial audit event
  await recordAudit({
    actor: { id: 'system-bootstrap', email: 'system@sentineliq.internal', role: 'SYSTEM' },
    action: 'SYSTEM_BOOTSTRAP_SEED',
    resourceType: 'System',
    resourceId: 'INIT-01',
    details: { totalIncidents: incidents.length, normalizedEvents: normalized.length }
  });

  console.log('[SentinelIQ-Seed] Seed completed successfully!');
}

module.exports = {
  seedInitialData
};
