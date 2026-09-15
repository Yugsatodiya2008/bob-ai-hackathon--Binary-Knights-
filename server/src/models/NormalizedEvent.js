const mongoose = require('mongoose');

const normalizedEventSchema = new mongoose.Schema({
  eventId: {
    type: String,
    required: true,
    unique: true,
    index: true
  },
  rawEventRef: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'RawEvent',
    required: true,
    index: true
  },
  source: {
    type: String,
    required: true,
    index: true
  },
  timestamp: {
    type: Date,
    required: true,
    index: true
  },
  eventType: {
    type: String,
    required: true,
    index: true
  },
  sourceIp: {
    type: String,
    index: true
  },
  destinationIp: {
    type: String,
    index: true
  },
  domain: {
    type: String,
    index: true
  },
  fileHash: {
    type: String,
    index: true
  },
  user: {
    type: String,
    index: true
  },
  processName: {
    type: String
  },
  severity: {
    type: String,
    enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
    default: 'MEDIUM',
    index: true
  },
  tlp: {
    type: String,
    enum: ['CLEAR', 'GREEN', 'AMBER', 'AMBER_STRICT', 'RED'],
    default: 'AMBER',
    index: true
  },
  confidence: {
    type: Number,
    min: 0,
    max: 100,
    default: 50
  },
  rawAttributes: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
  }
}, {
  timestamps: true
});

module.exports = mongoose.model('NormalizedEvent', normalizedEventSchema);
