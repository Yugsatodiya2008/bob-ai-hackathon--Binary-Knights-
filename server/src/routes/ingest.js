const express = require('express');
const router = express.Router();
const { ingestPayload } = require('../services/ingestionService');
const QuarantineEvent = require('../models/QuarantineEvent');
const RawEvent = require('../models/RawEvent');

// POST /api/v1/ingest/:sourceType
router.post('/ingest/:sourceType', async (req, res) => {
  const { sourceType } = req.params;
  const rawPayload = req.body;
  const headers = req.headers;

  const result = await ingestPayload({ sourceType, rawPayload, headers });

  if (result.status === 'QUARANTINED') {
    return res.status(422).json({
      success: false,
      message: 'Payload malformed or unsupported; quarantined for analyst review without data loss',
      data: result
    });
  }

  return res.status(201).json({
    success: true,
    message: 'Event successfully ingested into raw_events',
    data: result
  });
});

// GET /api/v1/quarantine - View quarantined events (FR-2.4)
router.get('/quarantine', async (req, res) => {
  try {
    const { status = 'QUARANTINED', limit = 50 } = req.query;
    const query = status === 'ALL' ? {} : { status };
    const items = await QuarantineEvent.find(query).sort({ quarantinedAt: -1 }).limit(Number(limit));
    res.json({ success: true, count: items.length, data: items });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/v1/raw-events - View raw events
router.get('/raw-events', async (req, res) => {
  try {
    const { limit = 50 } = req.query;
    const items = await RawEvent.find().sort({ ingestedAt: -1 }).limit(Number(limit));
    res.json({ success: true, count: items.length, data: items });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

module.exports = router;
