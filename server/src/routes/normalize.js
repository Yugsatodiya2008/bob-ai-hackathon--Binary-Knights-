const express = require('express');
const router = express.Router();
const { processPendingRawEvents, normalizeRawEvent } = require('../services/normalizationService');
const NormalizedEvent = require('../models/NormalizedEvent');
const RawEvent = require('../models/RawEvent');

// POST /api/v1/normalize/batch - Trigger processing of received raw events
router.post('/normalize/batch', async (req, res) => {
  try {
    const limit = Number(req.query.limit) || 100;
    const normalized = await processPendingRawEvents(limit);
    res.json({
      success: true,
      processedCount: normalized.length,
      data: normalized
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/v1/normalized-events - Retrieve normalized events with query filter
router.get('/normalized-events', async (req, res) => {
  try {
    const { source, severity, tlp, limit = 50 } = req.query;
    const filter = {};
    if (source) filter.source = source;
    if (severity) filter.severity = severity;
    if (tlp) filter.tlp = tlp;

    const events = await NormalizedEvent.find(filter).sort({ timestamp: -1 }).limit(Number(limit));
    res.json({
      success: true,
      count: events.length,
      data: events
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

module.exports = router;
