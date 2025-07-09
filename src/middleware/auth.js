const jwtService = require("../utils/jwt");
const Token = require("../models/Token");
const User = require("../models/User");
const logger = require("../utils/logger");

// Extract token from request headers
const extractToken = (req) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return null;
  }
  return authHeader.substring(7);
};

// Verify JWT token and attach user to request
const verifyToken = async (req, res, next) => {
  try {
    const token = extractToken(req);
    if (!token) {
      return res.status(401).json({
        error: "access_denied",
        error_description: "No token provided",
      });
    }

    // Verify the token
    const decoded = jwtService.verifyAccessToken(token);

    // Check if token is blacklisted/revoked
    const tokenDoc = await Token.findValidToken(token, "access_token");
    if (!tokenDoc) {
      return res.status(401).json({
        error: "invalid_token",
        error_description: "Token has been revoked",
      });
    }

    // Get user information
    const user = await User.findById(decoded.sub).select("-password");
    if (!user || !user.isActive) {
      return res.status(401).json({
        error: "invalid_token",
        error_description: "User not found or inactive",
      });
    }

    // Attach user and token info to request
    req.user = user;
    req.token = decoded;
    req.tokenDoc = tokenDoc;

    next();
  } catch (error) {
    logger.error("Token verification failed:", error.message);
    return res.status(401).json({
      error: "invalid_token",
      error_description: "Invalid or expired token",
    });
  }
};

// Optional authentication - doesn't fail if no token
const optionalAuth = async (req, res, next) => {
  try {
    const token = extractToken(req);
    if (!token) {
      return next();
    }

    const decoded = jwtService.verifyAccessToken(token);
    const tokenDoc = await Token.findValidToken(token, "access_token");

    if (tokenDoc) {
      const user = await User.findById(decoded.sub).select("-password");
      if (user && user.isActive) {
        req.user = user;
        req.token = decoded;
        req.tokenDoc = tokenDoc;
      }
    }

    next();
  } catch (error) {
    // Continue without authentication
    next();
  }
};

// Role-based access control middleware
const requireRole = (roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        error: "access_denied",
        error_description: "Authentication required",
      });
    }

    const userRole = req.user.role;
    const allowedRoles = Array.isArray(roles) ? roles : [roles];

    if (!allowedRoles.includes(userRole)) {
      return res.status(403).json({
        error: "insufficient_scope",
        error_description: "Insufficient permissions",
      });
    }

    next();
  };
};

// Scope-based access control middleware
const requireScope = (requiredScopes) => {
  return (req, res, next) => {
    if (!req.token) {
      return res.status(401).json({
        error: "access_denied",
        error_description: "Authentication required",
      });
    }

    const tokenScopes = req.token.scopes || [];
    const scopes = Array.isArray(requiredScopes)
      ? requiredScopes
      : [requiredScopes];

    const hasAllScopes = scopes.every((scope) => tokenScopes.includes(scope));
    if (!hasAllScopes) {
      return res.status(403).json({
        error: "insufficient_scope",
        error_description: "Insufficient scopes",
      });
    }

    next();
  };
};

// Client authentication middleware (for OAuth2)
const authenticateClient = async (req, res, next) => {
  try {
    const Client = require("../models/Client");

    // Try Basic Auth first
    const authHeader = req.headers.authorization;
    let clientId, clientSecret;

    if (authHeader && authHeader.startsWith("Basic ")) {
      const credentials = Buffer.from(
        authHeader.substring(6),
        "base64"
      ).toString();
      const [id, secret] = credentials.split(":");
      clientId = id;
      clientSecret = secret;
    } else {
      // Try form parameters
      clientId = req.body.client_id;
      clientSecret = req.body.client_secret;
    }

    if (!clientId) {
      return res.status(401).json({
        error: "invalid_client",
        error_description: "Client ID is required",
      });
    }

    const client = await Client.findByClientId(clientId);
    if (!client || !client.isActive) {
      return res.status(401).json({
        error: "invalid_client",
        error_description: "Invalid or inactive client",
      });
    }

    // For confidential clients, verify secret
    if (client.clientType === "confidential") {
      if (!clientSecret) {
        return res.status(401).json({
          error: "invalid_client",
          error_description:
            "Client secret is required for confidential clients",
        });
      }

      if (client.clientSecret !== clientSecret) {
        return res.status(401).json({
          error: "invalid_client",
          error_description: "Invalid client secret",
        });
      }
    }

    req.client = client;
    next();
  } catch (error) {
    logger.error("Client authentication failed:", error.message);
    return res.status(401).json({
      error: "invalid_client",
      error_description: "Client authentication failed",
    });
  }
};

// Rate limiting per user
const userRateLimit = (maxRequests = 100, windowMs = 15 * 60 * 1000) => {
  const rateLimit = require("express-rate-limit");

  return rateLimit({
    windowMs,
    max: (req) => {
      // Higher limits for authenticated users
      if (req.user) {
        return maxRequests * 2;
      }
      return maxRequests;
    },
    keyGenerator: (req) => {
      return req.user ? req.user._id.toString() : req.ip;
    },
    message: {
      error: "rate_limit_exceeded",
      error_description: "Too many requests",
    },
    standardHeaders: true,
    legacyHeaders: false,
  });
};

// Audit logging middleware
const auditLog = (action) => {
  return (req, res, next) => {
    const originalSend = res.send;

    res.send = function (data) {
      const logData = {
        timestamp: new Date().toISOString(),
        action,
        method: req.method,
        path: req.path,
        ip: req.ip,
        userAgent: req.get("User-Agent"),
        userId: req.user?._id,
        clientId: req.client?.clientId,
        statusCode: res.statusCode,
        responseSize: data ? data.length : 0,
      };

      if (res.statusCode >= 400) {
        logger.warn("Audit log - Failed request:", logData);
      } else {
        logger.info("Audit log - Successful request:", logData);
      }

      originalSend.call(this, data);
    };

    next();
  };
};

module.exports = {
  verifyToken,
  optionalAuth,
  requireRole,
  requireScope,
  authenticateClient,
  userRateLimit,
  auditLog,
};
