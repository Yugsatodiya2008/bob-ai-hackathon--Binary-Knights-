const express = require('express');
const router = express.Router();
const { generateHeatmapData, mapIncidentToAttack } = require('../services/mitreService');
const { scoreIncident } = require('../services/scoringService');
const Incident = require('../models/Incident');
const { getTlpQueryFilter } = require('../middleware/auth');

// POST /api/v1/pipeline/run - Run full pipeline: normalize + correlate + score + mitre map
router.post('/pipeline/run', async (req, res) => {
  try {
    const { processPendingRawEvents } = require('../services/normalizationService');
    const { correlateAllUncorrelatedEvents } = require('../services/correlationService');

    // Step 1: Normalize
    const normalized = await processPendingRawEvents();

    // Step 2: Correlate
    const correlated = await correlateAllUncorrelatedEvents();

    // Step 3: Score + MITRE map each incident
    const incidentIds = [...new Set(correlated.map(c => c.incident._id.toString()))];
    const results = [];
    for (const id of incidentIds) {
      await mapIncidentToAttack(id);
      const scored = await scoreIncident(id);
      results.push(scored);
    }

    res.json({
      success: true,
      normalized: normalized.length,
      correlated: correlated.length,
      incidentsScored: results.length,
      data: results
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/v1/incidents/triage - Ranked triage queue with Query-layer TLP enforcement (FR-6.2, §0 #4)
router.get('/incidents/triage', async (req, res) => {
  try {
    const { limit = 50 } = req.query;
    const baseFilter = { status: { $in: ['OPEN', 'IN_TRIAGE', 'ESCALATED'] } };
    const filter = getTlpQueryFilter(req.user, baseFilter);

    const incidents = await Incident.find(filter)
      .sort({ priorityScore: -1 })
      .limit(Number(limit))
      .populate('eventRefs');

    res.json({
      success: true,
      count: incidents.length,
      userClearance: req.user ? req.user.clearance : 'UNSET',
      data: incidents.map(inc => ({
        _id: inc._id,
        incidentId: inc.incidentId,
        title: inc.title,
        severity: inc.severity,
        status: inc.status,
        tlp: inc.tlp,
        confidenceScore: inc.confidenceScore,
        confidenceFactors: inc.confidenceFactors,
        priorityScore: inc.priorityScore,
        priorityFactors: inc.priorityFactors,
        mitreAttack: inc.mitreAttack,
        eventCount: (inc.eventRefs && inc.eventRefs.length) ? inc.eventRefs.length : 0,
        createdAt: inc.createdAt
      }))
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/v1/mitre/heatmap - ATT&CK heatmap data (FR-5.3)
router.get('/mitre/heatmap', async (req, res) => {
  try {
    const heatmap = await generateHeatmapData();
    res.json({ success: true, data: heatmap });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

module.exports = router;
