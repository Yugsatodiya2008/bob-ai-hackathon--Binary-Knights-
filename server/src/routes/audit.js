const express = require('express');
const router = express.Router();
const AuditLog = require('../models/AuditLog');
const { requireRole } = require('../middleware/auth');

// GET /api/v1/audit-logs - Query immutable audit logs (Admin and Commander only per FR-11.2)
router.get('/audit-logs', requireRole('ADMIN', 'COMMANDER'), async (req, res) => {
  try {
    const { action, resourceType, limit = 100, skip = 0 } = req.query;
    const filter = {};
    if (action) filter.action = action;
    if (resourceType) filter.resourceType = resourceType;

    const logs = await AuditLog.find(filter)
      .sort({ timestamp: -1 })
      .skip(Number(skip))
      .limit(Number(limit));

    const total = await AuditLog.countDocuments(filter);

    res.json({
      success: true,
      total,
      count: logs.length,
      data: logs
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

module.exports = router;
