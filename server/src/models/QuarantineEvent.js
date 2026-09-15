const mongoose = require('mongoose');

const quarantineEventSchema = new mongoose.Schema({
  rawEventRef: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'RawEvent',
    required: false
  },
  sourceType: {
    type: String,
    required: true,
    index: true
  },
  rawPayload: {
    type: mongoose.Schema.Types.Mixed,
    required: true
  },
  reason: {
    type: String,
    required: true
  },
  validationErrors: [{
    path: String,
    message: String
  }],
  status: {
    type: String,
    enum: ['QUARANTINED', 'RESOLVED', 'IGNORED'],
    default: 'QUARANTINED',
    index: true
  },
  quarantinedAt: {
    type: Date,
    default: Date.now,
    index: true
  },
  resolvedBy: {
    type: String,
    default: null
  },
  resolvedAt: {
    type: Date,
    default: null
  }
}, {
  timestamps: true
});

module.exports = mongoose.model('QuarantineEvent', quarantineEventSchema);
