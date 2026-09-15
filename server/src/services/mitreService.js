const mitreData = require('../data/mitre-attack-v14.json');
const NormalizedEvent = require('../models/NormalizedEvent');
const Incident = require('../models/Incident');

// ============================================================================
// FR-5.2: Rule-based MITRE ATT&CK Technique Mapping with Explainability
// Air-gapped: reads only from local cache, no external API calls (§0 #6)
// ============================================================================

// Keyword/pattern rules mapping observable indicators to ATT&CK techniques
const MAPPING_RULES = [
  {
    techniqueId: 'T1059.001',
    patterns: { processName: /powershell/i, rawAttributes: /powershell|bypass|encodedcommand/i },
    minConfidence: 75
  },
  {
    techniqueId: 'T1059.003',
    patterns: { processName: /cmd\.exe/i, rawAttributes: /cmd\.exe|command\s*shell/i },
    minConfidence: 70
  },
  {
    techniqueId: 'T1003.001',
    patterns: { processName: /lsass|mimikatz/i, rawAttributes: /lsass|credential.*dump|mimikatz/i },
    minConfidence: 90
  },
  {
    techniqueId: 'T1003',
    patterns: { rawAttributes: /credential.*dump|ntds|secretsdump/i },
    minConfidence: 80
  },
  {
    techniqueId: 'T1110',
    patterns: { eventType: /brute.*force|auth.*fail/i, rawAttributes: /brute|multiple.*failed.*login/i },
    minConfidence: 70
  },
  {
    techniqueId: 'T1071.001',
    patterns: { rawAttributes: /c2.*beacon|cobalt.*strike|http.*beacon/i },
    minConfidence: 85
  },
  {
    techniqueId: 'T1486',
    patterns: { rawAttributes: /ransom|encrypt.*impact|lockbit|wannacry/i },
    minConfidence: 90
  },
  {
    techniqueId: 'T1566.001',
    patterns: { rawAttributes: /phish|spearphish|malicious.*attachment/i },
    minConfidence: 75
  },
  {
    techniqueId: 'T1190',
    patterns: { rawAttributes: /exploit.*public|cve-\d{4}/i },
    minConfidence: 80
  },
  {
    techniqueId: 'T1078',
    patterns: { rawAttributes: /valid.*account|compromised.*credential|stolen.*cred/i },
    minConfidence: 70
  },
  {
    techniqueId: 'T1055',
    patterns: { rawAttributes: /process.*inject|dll.*inject|hollowing/i },
    minConfidence: 85
  },
  {
    techniqueId: 'T1105',
    patterns: { rawAttributes: /tool.*transfer|download.*payload|ingress/i },
    minConfidence: 70
  },
  {
    techniqueId: 'T1041',
    patterns: { rawAttributes: /exfil.*c2|data.*exfiltration/i },
    minConfidence: 80
  }
];

const lookupTechnique = (techniqueId) => {
  return mitreData.techniques.find(t => t.id === techniqueId) || null;
};

const lookupTactic = (tacticId) => {
  return mitreData.tactics.find(t => t.id === tacticId) || null;
};

const testField = (event, field, regex) => {
  if (field === 'rawAttributes') {
    const serialized = JSON.stringify(event.rawAttributes || {});
    return regex.test(serialized);
  }
  const val = event[field];
  return val && regex.test(val);
};

const mapEventToTechniques = (event) => {
  const matches = [];
  for (const rule of MAPPING_RULES) {
    const matchedFactors = [];
    for (const [field, regex] of Object.entries(rule.patterns)) {
      if (testField(event, field, regex)) {
        matchedFactors.push(`${field} matched pattern ${regex.source}`);
      }
    }
    if (matchedFactors.length > 0) {
      const technique = lookupTechnique(rule.techniqueId);
      if (technique) {
        const tactic = lookupTactic(technique.tactic);
        matches.push({
          tactic: tactic ? tactic.name : technique.tactic,
          techniqueId: technique.id,
          techniqueName: technique.name,
          confidence: rule.minConfidence,
          factors: matchedFactors
        });
      }
    }
  }
  return matches;
};

const mapIncidentToAttack = async (incidentId) => {
  const incident = await Incident.findById(incidentId);
  if (!incident) throw new Error('Incident not found');

  const events = await NormalizedEvent.find({ _id: { $in: incident.eventRefs } });
  const allMappings = [];
  const seenTechniques = new Set();

  for (const ev of events) {
    const techniques = mapEventToTechniques(ev);
    for (const t of techniques) {
      if (!seenTechniques.has(t.techniqueId)) {
        seenTechniques.add(t.techniqueId);
        allMappings.push(t);
      } else {
        // Merge factors into existing
        const existing = allMappings.find(m => m.techniqueId === t.techniqueId);
        if (existing) {
          existing.factors = [...new Set([...existing.factors, ...t.factors])];
          existing.confidence = Math.max(existing.confidence, t.confidence);
        }
      }
    }
  }

  incident.mitreAttack = allMappings;
  await incident.save();
  return allMappings;
};

// FR-5.3: Heatmap data endpoint
const generateHeatmapData = async () => {
  const incidents = await Incident.find({ status: { $in: ['OPEN', 'IN_TRIAGE', 'ESCALATED'] } });
  const heatmap = {};

  for (const inc of incidents) {
    for (const mapping of inc.mitreAttack) {
      const key = `${mapping.tactic}::${mapping.techniqueId}`;
      if (!heatmap[key]) {
        heatmap[key] = {
          tactic: mapping.tactic,
          techniqueId: mapping.techniqueId,
          techniqueName: mapping.techniqueName,
          count: 0,
          avgConfidence: 0,
          incidentRefs: []
        };
      }
      heatmap[key].count += 1;
      heatmap[key].avgConfidence = Math.round(
        ((heatmap[key].avgConfidence * (heatmap[key].count - 1)) + mapping.confidence) / heatmap[key].count
      );
      heatmap[key].incidentRefs.push(inc.incidentId);
    }
  }

  return Object.values(heatmap).sort((a, b) => b.count - a.count);
};

module.exports = {
  mapEventToTechniques,
  mapIncidentToAttack,
  generateHeatmapData,
  lookupTechnique,
  lookupTactic,
  MAPPING_RULES
};
