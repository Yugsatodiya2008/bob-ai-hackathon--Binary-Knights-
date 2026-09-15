const express = require('express');
const router = express.Router();
const { generateBluf, approveBluf, lockBluf } = require('../services/blufService');
const BlufReport = require('../models/BlufReport');
const Incident = require('../models/Incident');
const { requireRole, hasTlpAccess } = require('../middleware/auth');
const { recordAudit } = require('../middleware/audit');

// POST /api/v1/incidents/:id/bluf/generate - Generate BLUF (FR-7.1)
router.post('/incidents/:id/bluf/generate', requireRole('ANALYST', 'COMMANDER', 'ADMIN'), async (req, res) => {
  try {
    const incident = await Incident.findById(req.params.id);
    if (!incident) {
      return res.status(404).json({ success: false, error: 'Incident not found' });
    }

    if (!hasTlpAccess(req.user, incident.tlp)) {
      return res.status(403).json({
        success: false,
        error: `Access Denied: Incident is classified as TLP:${incident.tlp}, exceeding user clearance TLP:${req.user.clearance}`
      });
    }

    const report = await generateBluf(req.params.id);

    await recordAudit({
      actor: req.user,
      action: 'BLUF_GENERATED',
      resourceType: 'BLUF_REPORT',
      resourceId: report.reportId,
      details: { incidentId: req.params.id }
    });

    res.status(201).json({ success: true, data: report });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
});

// POST /api/v1/bluf/:reportId/approve - Analyst or Commander approval (FR-7.3, §0 #1)
router.post('/bluf/:reportId/approve', requireRole('ANALYST', 'COMMANDER'), async (req, res) => {
  try {
    const { analystName } = req.body;
    if (!analystName) {
      return res.status(400).json({ success: false, error: 'Analyst name/ID is required for BLUF approval' });
    }
    const report = await approveBluf(req.params.reportId, analystName);

    await recordAudit({
      actor: req.user,
      action: 'BLUF_APPROVED',
      resourceType: 'BLUF_REPORT',
      resourceId: report.reportId,
      details: { approvedBy: analystName, role: req.user.role }
    });

    res.json({ success: true, data: report });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
});

// POST /api/v1/bluf/:reportId/lock - Commander / Analyst lock (FR-7.3)
router.post('/bluf/:reportId/lock', requireRole('ANALYST', 'COMMANDER', 'ADMIN'), async (req, res) => {
  try {
    const report = await lockBluf(req.params.reportId);

    await recordAudit({
      actor: req.user,
      action: 'BLUF_LOCKED',
      resourceType: 'BLUF_REPORT',
      resourceId: report.reportId,
      details: { lockedBy: req.user.email || req.user.id }
    });

    res.json({ success: true, data: report });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
});

// GET /api/v1/bluf - List BLUF reports respecting TLP clearance
router.get('/bluf', async (req, res) => {
  try {
    const { status, limit = 50 } = req.query;
    const filter = {};
    if (status) filter.status = status;
    const reports = await BlufReport.find(filter)
      .sort({ generatedAt: -1 })
      .limit(Number(limit))
      .populate('incidentRef')
      .populate('keyFindings.supportingEvidenceRefs');

    // Filter reports according to user's TLP clearance on incident
    const accessibleReports = reports.filter(r => {
      if (!r.incidentRef) return true;
      return hasTlpAccess(req.user, r.incidentRef.tlp);
    });

    res.json({ success: true, count: accessibleReports.length, data: accessibleReports });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

module.exports = router;
