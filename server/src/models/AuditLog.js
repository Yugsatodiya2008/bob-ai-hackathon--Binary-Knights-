const mongoose = require('mongoose');

const auditLogSchema = new mongoose.Schema({
  timestamp: {
    type: Date,
    default: Date.now,
    index: true,
    immutable: true
  },
  userId: {
    type: String,
    required: true,
    index: true
  },
  userEmail: {
    type: String
  },
  role: {
    type: String,
    enum: ['ANALYST', 'COMMANDER', 'ADMIN', 'SYSTEM'],
    required: true,
    index: true
  },
  action: {
    type: String,
    required: true,
    index: true
  },
  resourceType: {
    type: String,
    required: true,
    index: true
  },
  resourceId: {
    type: String,
    index: true
  },
  details: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
  },
  ipAddress: {
    type: String,
    default: '127.0.0.1'
  }
}, {
  timestamps: false
});

module.exports = mongoose.model('AuditLog', auditLogSchema);
