const mongoose = require('mongoose');

const rawEventSchema = new mongoose.Schema({
  sourceType: {
    type: String,
    required: true,
    index: true,
    enum: ['crowdstrike', 'splunkevent', 'suricata', 'generic_webhook']
  },
  payload: {
    type: mongoose.Schema.Types.Mixed,
    required: true
  },
  headers: {
    type: Map,
    of: String,
    default: {}
  },
  payloadHash: {
    type: String,
    required: true,
    index: true
  },
  status: {
    type: String,
    enum: ['RECEIVED', 'PROCESSED', 'QUARANTINED'],
    default: 'RECEIVED',
    index: true
  },
  ingestedAt: {
    type: Date,
    default: Date.now,
    index: true
  }
}, {
  timestamps: true
});

module.exports = mongoose.model('RawEvent', rawEventSchema);
