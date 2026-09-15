const express = require('express');
const router = express.Router();
const QuarantineEvent = require('../models/QuarantineEvent');
const { recordAudit } = require('../middleware/audit');
const { requireRole } = require('../middleware/auth');

// GET /api/v1/quarantine - List quarantined events (FR-2.4, §0 #3)
router.get('/quarantine', async (req, res) => {
  try {
    const { status, sourceType, limit = 50, skip = 0 } = req.query;
    const filter = {};
    if (status) filter.status = status;
    if (sourceType) filter.sourceType = sourceType;

    const events = await QuarantineEvent.find(filter)
      .sort({ quarantinedAt: -1 })
      .skip(Number(skip))
      .limit(Number(limit));

    const total = await QuarantineEvent.countDocuments(filter);

    res.json({
      success: true,
      total,
      count: events.length,
      data: events
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/v1/quarantine/:id - Get quarantined event detail
router.get('/quarantine/:id', async (req, res) => {
  try {
    const event = await QuarantineEvent.findById(req.params.id);
    if (!event) {
      return res.status(404).json({ success: false, error: 'Quarantine record not found' });
    }
    res.json({ success: true, data: event });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// PATCH /api/v1/quarantine/:id/review - Review/update quarantine status with audit log
router.patch('/quarantine/:id/review', requireRole('ANALYST', 'ADMIN'), async (req, res) => {
  try {
    const { status, notes } = req.body;
    if (!['RESOLVED', 'IGNORED', 'QUARANTINED'].includes(status)) {
      return res.status(400).json({ success: false, error: 'Invalid status' });
    }

    const event = await QuarantineEvent.findById(req.params.id);
    if (!event) {
      return res.status(404).json({ success: false, error: 'Quarantine record not found' });
    }

    const previousStatus = event.status;
    event.status = status;
    event.resolvedBy = req.user.email || req.user.id;
    event.resolvedAt = new Date();
    await event.save();

    // Immutable audit record
    await recordAudit({
      actor: req.user,
      action: 'QUARANTINE_REVIEWED',
      resourceType: 'QuarantineEvent',
      resourceId: event._id.toString(),
      details: { previousStatus, newStatus: status, notes },
      ipAddress: req.ip || '127.0.0.1'
    });

    res.json({ success: true, data: event });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

module.exports = router;
