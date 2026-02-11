const jwt = require("jsonwebtoken");
const config = require("../config");

function verifyAccessToken(req, res, next) {
  const authHeader = req.headers.authorization || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : "";

  if (!token) {
    return res.status(401).json({ message: "Missing access token" });
  }

  try {
    const payload = jwt.verify(token, config.jwtSecret);
    req.user = payload;
    return next();
  } catch (error) {
    return res.status(401).json({ message: "Invalid or expired access token" });
  }
}

function requireRole(allowedRoles) {
  return (req, res, next) => {
    const role = normalizeRole(req.user && req.user.role);
    if (!role || !allowedRoles.includes(role)) {
      return res.status(403).json({ message: "Insufficient role" });
    }
    return next();
  };
}

function normalizeRole(role) {
  if (!role) {
    return role;
  }

  const legacyMap = {
    ADMIN: "TOP_SECRET",
    OFFICER: "CONFIDENTIAL",
    AUDITOR: "RESTRICTED"
  };

  return legacyMap[role] || role;
}

function requireClearance(minClearance) {
  return (req, res, next) => {
    const clearanceLevel = req.user && req.user.clearanceLevel;
    if (!clearanceLevel || clearanceLevel < minClearance) {
      return res.status(403).json({ message: "Insufficient clearance" });
    }
    return next();
  };
}

module.exports = {
  verifyAccessToken,
  requireRole,
  requireClearance
};
