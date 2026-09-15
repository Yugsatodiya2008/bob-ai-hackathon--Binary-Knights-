const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'sentineliq-dev-insecure-secret-key-2026';

const TLP_HIERARCHY = {
  CLEAR: 0,
  GREEN: 1,
  AMBER: 2,
  AMBER_STRICT: 3,
  RED: 4
};

const TLP_ALLOWED = {
  CLEAR: ['CLEAR'],
  GREEN: ['CLEAR', 'GREEN'],
  AMBER: ['CLEAR', 'GREEN', 'AMBER'],
  AMBER_STRICT: ['CLEAR', 'GREEN', 'AMBER', 'AMBER_STRICT'],
  RED: ['CLEAR', 'GREEN', 'AMBER', 'AMBER_STRICT', 'RED']
};

/**
 * Authentication and TLP Clearance middleware
 * Resolves user from JWT or Dev Headers:
 *   - X-User-Id
 *   - X-User-Email
 *   - X-User-Role: ANALYST | COMMANDER | ADMIN
 *   - X-User-Clearance: CLEAR | GREEN | AMBER | AMBER_STRICT | RED
 */
function authMiddleware(req, res, next) {
  let user = null;

  // 1. Check Bearer token
  const authHeader = req.headers['authorization'];
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.split(' ')[1];
    try {
      user = jwt.verify(token, JWT_SECRET);
    } catch (err) {
      return res.status(401).json({ success: false, error: 'Invalid or expired token' });
    }
  }

  // 2. Check dev headers if no token or token parsed
  const roleHeader = req.headers['x-user-role'];
  const clearanceHeader = req.headers['x-user-clearance'];
  const idHeader = req.headers['x-user-id'];
  const emailHeader = req.headers['x-user-email'];

  if (!user) {
    const role = (roleHeader || 'ANALYST').toUpperCase();
    const clearance = (clearanceHeader || 'RED').toUpperCase();
    const id = idHeader || 'analyst-dev-01';
    const email = emailHeader || 'analyst@sentineliq.internal';

    user = { id, email, role, clearance };
  }

  // Validate clearance
  if (!TLP_HIERARCHY.hasOwnProperty(user.clearance)) {
    user.clearance = 'AMBER';
  }

  // Attach allowed TLPs to user context
  user.allowedTlps = TLP_ALLOWED[user.clearance] || ['CLEAR', 'GREEN', 'AMBER'];

  req.user = user;
  next();
}

/**
 * Role-based access control guard
 */
function requireRole(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user || !allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        error: `Forbidden: Role '${req.user ? req.user.role : 'ANONYMOUS'}' lacks required permissions [${allowedRoles.join(', ')}]`
      });
    }
    next();
  };
}

/**
 * Query-layer TLP filter helper
 * Directly attaches MongoDB filter to enforce user clearance
 */
function getTlpQueryFilter(user, baseFilter = {}) {
  const allowed = user.allowedTlps || ['CLEAR'];
  return {
    ...baseFilter,
    tlp: { $in: allowed }
  };
}

/**
 * Validates single document access against user clearance
 */
function hasTlpAccess(user, docTlp) {
  if (!docTlp) return true;
  const docLevel = TLP_HIERARCHY[docTlp.toUpperCase()] ?? 4;
  const userLevel = TLP_HIERARCHY[user.clearance.toUpperCase()] ?? 0;
  return userLevel >= docLevel;
}

module.exports = {
  authMiddleware,
  requireRole,
  getTlpQueryFilter,
  hasTlpAccess,
  TLP_HIERARCHY,
  TLP_ALLOWED,
  JWT_SECRET
};
