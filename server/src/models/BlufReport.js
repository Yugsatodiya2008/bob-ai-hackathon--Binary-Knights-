const mongoose = require('mongoose');

const blufReportSchema = new mongoose.Schema({
  reportId: {
    type: String,
    required: true,
    unique: true,
    index: true
  },
  incidentRef: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Incident',
    required: true,
    index: true
  },
  executiveSummary: {
    type: String,
    required: true
  },
  keyFindings: [{
    statement: {
      type: String,
      required: true
    },
    supportingEvidenceRefs: [{
      type: mongoose.Schema.Types.ObjectId,
      ref: 'NormalizedEvent',
      required: true
    }]
  }],
  threatActorAttribution: {
    actorName: { type: String, default: 'UNKNOWN / UNATTRIBUTED' },
    confidence: { type: Number, default: 0 },
    evidenceRefs: [{
      type: mongoose.Schema.Types.ObjectId,
      ref: 'NormalizedEvent'
    }]
  },
  recommendedActions: [{
    action: { type: String, required: true },
    priority: { type: String, enum: ['IMMEDIATE', 'HIGH', 'ROUTINE'], default: 'HIGH' },
    requiresApproval: { type: Boolean, default: true }
  }],
  status: {
    type: String,
    enum: ['DRAFT', 'APPROVED', 'LOCKED'],
    default: 'DRAFT',
    index: true
  },
  approvedBy: {
    type: String,
    default: null
  },
  approvedAt: {
    type: Date,
    default: null
  },
  generatedAt: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true
});

module.exports = mongoose.model('BlufReport', blufReportSchema);
