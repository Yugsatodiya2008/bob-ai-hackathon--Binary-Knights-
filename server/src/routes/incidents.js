const express = require('express');
const router = express.Router();
const Incident = require('../models/Incident');
const { correlateAllUncorrelatedEvents } = require('../services/correlationService');
const { getTlpQueryFilter, hasTlpAccess, requireRole } = require('../middleware/auth');
const { recordAudit } = require('../middleware/audit');

// POST /api/v1/correlate - Trigger correlation run
router.post('/correlate', async (req, res) => {
  try {
    const results = await correlateAllUncorrelatedEvents();
    res.json({
      success: true,
      processedEvents: results.length,
      newIncidents: results.filter(r => r.createdNew).length,
      data: results
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/v1/incidents - List incidents with Query-Layer TLP Enforcement per §0 #4, FR-12.2
router.get('/incidents', async (req, res) => {
  try {
    const { status, severity, tlp, limit = 50 } = req.query;
    let baseFilter = {};
    if (status) baseFilter.status = status;
    if (severity) baseFilter.severity = severity;
    if (tlp) baseFilter.tlp = tlp;

    // Apply Query-Layer TLP filtering: User only sees incidents <= their clearance
    const filter = getTlpQueryFilter(req.user, baseFilter);

    const incidents = await Incident.find(filter)
      .sort({ priorityScore: -1, createdAt: -1 })
      .limit(Number(limit))
      .populate('eventRefs');

    res.json({ success: true, count: incidents.length, data: incidents });
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

// GET /api/v1/incidents/:id - Incident detail with TLP Clearance check per §0 #4
router.get('/incidents/:id', async (req, res) => {
  try {
    const mongoose = require('mongoose');
    let incident;
    if (mongoose.Types.ObjectId.isValid(req.params.id)) {
      incident = await Incident.findById(req.params.id).populate('eventRefs');
    } else {
      incident = await Incident.findOne({ incidentId: req.params.id }).populate('eventRefs');
    }
    if (!incident) {
      return res.status(404).json({ success: false, error: 'Incident not found' });
    }

    // Clearance check
    if (!hasTlpAccess(req.user, incident.tlp)) {
      return res.status(403).json({
        success: false,
        error: `Access Denied: Incident is classified as TLP:${incident.tlp}, exceeding user clearance TLP:${req.user.clearance}`
      });
    }

    res.json({ success: true, data: incident });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// PATCH /api/v1/incidents/:id/status - Human-in-the-loop status transition per §0 #1
router.patch('/incidents/:id/status', requireRole('ANALYST', 'COMMANDER', 'ADMIN'), async (req, res) => {
  try {
    const { status, analystName, rationale, signOffConfirmed } = req.body;
    const incident = await Incident.findById(req.params.id);
    if (!incident) {
      return res.status(404).json({ success: false, error: 'Incident not found' });
    }

    // Clearance check
    if (!hasTlpAccess(req.user, incident.tlp)) {
      return res.status(403).json({
        success: false,
        error: `Access Denied: Incident is classified as TLP:${incident.tlp}, exceeding user clearance TLP:${req.user.clearance}`
      });
    }

    // §0 Constraint: Autonomous incident closure is forbidden.
    // Incident closure strictly requires human analyst sign-off and rationale.
    if (status === 'CLOSED') {
      if (!signOffConfirmed || !analystName || !rationale) {
        return res.status(403).json({
          success: false,
          error: '§0 Constraint Violation: Incident closure strictly requires human analyst sign-off, name, and rationale.'
        });
      }
      incident.closureMetadata = {
        closedBy: analystName,
        closedAt: new Date(),
        rationale,
        signOffConfirmed: true
      };
    }

    const previousStatus = incident.status;
    incident.status = status;
    await incident.save();

    // Record immutable audit log
    await recordAudit({
      actor: req.user,
      action: 'INCIDENT_STATUS_CHANGE',
      resourceType: 'INCIDENT',
      resourceId: incident.incidentId,
      details: { previousStatus, newStatus: status, rationale, analystName },
      ipAddress: req.ip || '127.0.0.1'
    });

    res.json({ success: true, data: incident });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

module.exports = router;
