const mongoose = require('mongoose');

const incidentSchema = new mongoose.Schema({
  incidentId: {
    type: String,
    required: true,
    unique: true,
    index: true
  },
  title: {
    type: String,
    required: true
  },
  description: {
    type: String
  },
  severity: {
    type: String,
    enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
    default: 'MEDIUM',
    index: true
  },
  status: {
    type: String,
    enum: ['OPEN', 'IN_TRIAGE', 'ESCALATED', 'CLOSED'],
    default: 'OPEN',
    index: true
  },
  tlp: {
    type: String,
    enum: ['CLEAR', 'GREEN', 'AMBER', 'AMBER_STRICT', 'RED'],
    default: 'AMBER',
    index: true
  },
  confidenceScore: {
    type: Number,
    min: 0,
    max: 100,
    required: true
  },
  confidenceFactors: [{
    factor: { type: String, required: true },
    weight: { type: Number, required: true },
    score: { type: Number, required: true },
    reason: { type: String, required: true }
  }],
  priorityScore: {
    type: Number,
    min: 0,
    max: 100,
    required: true,
    index: true
  },
  priorityFactors: [{
    factor: { type: String, required: true },
    weight: { type: Number, required: true },
    score: { type: Number, required: true },
    reason: { type: String, required: true }
  }],
  mitreAttack: [{
    tactic: { type: String, required: true },
    techniqueId: { type: String, required: true },
    techniqueName: { type: String, required: true },
    confidence: { type: Number, required: true },
    factors: [{ type: String }]
  }],
  eventRefs: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'NormalizedEvent'
  }],
  assignedAnalyst: {
    id: String,
    name: String,
    email: String
  },
  closureMetadata: {
    closedBy: { type: String },
    closedAt: { type: Date },
    rationale: { type: String },
    signOffConfirmed: { type: Boolean, default: false }
  }
}, {
  timestamps: true
});

module.exports = mongoose.model('Incident', incidentSchema);
