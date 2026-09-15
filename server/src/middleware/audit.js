const AuditLog = require('../models/AuditLog');

/**
 * Record immutable audit log entry per §0 #1, FR-11.1, FR-11.2
 */
async function recordAudit({ actor, action, resourceType, resourceId, details = {}, ipAddress = '127.0.0.1' }) {
  try {
    const entry = await AuditLog.create({
      timestamp: new Date(),
      userId: actor?.id || 'system',
      userEmail: actor?.email || 'system@sentineliq.internal',
      role: actor?.role || 'SYSTEM',
      action,
      resourceType,
      resourceId: String(resourceId || ''),
      details,
      ipAddress
    });
    return entry;
  } catch (err) {
    console.error('[SentinelIQ-Audit] Failed to persist audit log:', err.message);
    throw err;
  }
}

/**
 * Express middleware helper to log mutating requests
 */
function auditMiddleware(action, resourceType) {
  return async (req, res, next) => {
    // Wrap res.json to capture outcome
    const originalJson = res.json.bind(res);
    res.json = function(data) {
      if (res.statusCode >= 200 && res.statusCode < 300) {
        recordAudit({
          actor: req.user,
          action,
          resourceType,
          resourceId: req.params.id || req.body.incidentId || req.body.reportId || '',
          details: {
            body: req.body,
            query: req.query,
            status: res.statusCode
          },
          ipAddress: req.ip || req.connection?.remoteAddress || '127.0.0.1'
        }).catch(e => console.error('[AuditMiddleware] Logging error:', e.message));
      }
      return originalJson(data);
    };
    next();
  };
}

module.exports = {
  recordAudit,
  auditMiddleware
};
