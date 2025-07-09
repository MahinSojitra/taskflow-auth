const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const logger = require("./logger");

class JWTService {
  constructor() {
    this.accessSecret = process.env.JWT_ACCESS_SECRET;
    this.refreshSecret = process.env.JWT_REFRESH_SECRET;
    this.idSecret = process.env.JWT_ID_SECRET;

    if (!this.accessSecret || !this.refreshSecret || !this.idSecret) {
      throw new Error("JWT secrets are not configured");
    }
  }

  // Generate access token
  generateAccessToken(user, clientId, scopes = []) {
    const payload = {
      sub: user._id.toString(),
      aud: clientId,
      iss: process.env.HOST || "http://localhost:3000",
      iat: Math.floor(Date.now() / 1000),
      exp:
        Math.floor(Date.now() / 1000) +
        parseInt(process.env.JWT_ACCESS_EXPIRES_IN || "900"), // 15 minutes default
      type: "access_token",
      scopes: scopes,
      user: {
        id: user._id.toString(),
        email: user.email,
        username: user.username,
        role: user.role,
        firstName: user.firstName,
        lastName: user.lastName,
      },
    };

    try {
      return jwt.sign(payload, this.accessSecret, { algorithm: "HS256" });
    } catch (error) {
      logger.error("Error generating access token:", error);
      throw new Error("Failed to generate access token");
    }
  }

  // Generate refresh token
  generateRefreshToken(user, clientId, scopes = []) {
    const payload = {
      sub: user._id.toString(),
      aud: clientId,
      iss: process.env.HOST || "http://localhost:3000",
      iat: Math.floor(Date.now() / 1000),
      exp:
        Math.floor(Date.now() / 1000) +
        parseInt(process.env.JWT_REFRESH_EXPIRES_IN || "604800"), // 7 days default
      type: "refresh_token",
      scopes: scopes,
      jti: crypto.randomBytes(32).toString("hex"), // Unique token ID for rotation
    };

    try {
      return jwt.sign(payload, this.refreshSecret, { algorithm: "HS256" });
    } catch (error) {
      logger.error("Error generating refresh token:", error);
      throw new Error("Failed to generate refresh token");
    }
  }

  // Generate ID token (OpenID Connect)
  generateIdToken(user, clientId, scopes = [], nonce = null) {
    const now = Math.floor(Date.now() / 1000);
    const payload = {
      iss: process.env.HOST || "http://localhost:3000",
      sub: user._id.toString(),
      aud: clientId,
      exp: now + parseInt(process.env.JWT_ID_EXPIRES_IN || "3600"), // 1 hour default
      iat: now,
      auth_time: now,
      type: "id_token",
    };

    // Add standard OpenID Connect claims
    if (scopes.includes("profile")) {
      payload.name = user.fullName;
      payload.given_name = user.firstName;
      payload.family_name = user.lastName;
      payload.preferred_username = user.username;
      payload.picture = user.profile?.avatar;
      payload.locale = user.preferences?.language || "en";
      payload.updated_at = Math.floor(user.updatedAt.getTime() / 1000);
    }

    if (scopes.includes("email")) {
      payload.email = user.email;
      payload.email_verified = user.isEmailVerified;
    }

    // Add custom claims
    payload.role = user.role;
    payload.account_type = user.accountType;

    // Add nonce if provided (for OpenID Connect)
    if (nonce) {
      payload.nonce = nonce;
    }

    try {
      return jwt.sign(payload, this.idSecret, { algorithm: "HS256" });
    } catch (error) {
      logger.error("Error generating ID token:", error);
      throw new Error("Failed to generate ID token");
    }
  }

  // Verify access token
  verifyAccessToken(token) {
    try {
      const decoded = jwt.verify(token, this.accessSecret, {
        algorithms: ["HS256"],
        issuer: process.env.HOST || "http://localhost:3000",
      });

      if (decoded.type !== "access_token") {
        throw new Error("Invalid token type");
      }

      return decoded;
    } catch (error) {
      logger.error("Error verifying access token:", error.message);
      throw new Error("Invalid access token");
    }
  }

  // Verify refresh token
  verifyRefreshToken(token) {
    try {
      const decoded = jwt.verify(token, this.refreshSecret, {
        algorithms: ["HS256"],
        issuer: process.env.HOST || "http://localhost:3000",
      });

      if (decoded.type !== "refresh_token") {
        throw new Error("Invalid token type");
      }

      return decoded;
    } catch (error) {
      logger.error("Error verifying refresh token:", error.message);
      throw new Error("Invalid refresh token");
    }
  }

  // Verify ID token
  verifyIdToken(token) {
    try {
      const decoded = jwt.verify(token, this.idSecret, {
        algorithms: ["HS256"],
        issuer: process.env.HOST || "http://localhost:3000",
      });

      if (decoded.type !== "id_token") {
        throw new Error("Invalid token type");
      }

      return decoded;
    } catch (error) {
      logger.error("Error verifying ID token:", error.message);
      throw new Error("Invalid ID token");
    }
  }

  // Decode token without verification (for debugging)
  decodeToken(token) {
    try {
      return jwt.decode(token, { complete: true });
    } catch (error) {
      logger.error("Error decoding token:", error.message);
      throw new Error("Invalid token format");
    }
  }

  // Check if token is expired
  isTokenExpired(token) {
    try {
      const decoded = jwt.decode(token);
      if (!decoded || !decoded.exp) {
        return true;
      }
      return decoded.exp < Math.floor(Date.now() / 1000);
    } catch (error) {
      return true;
    }
  }

  // Get token expiration time
  getTokenExpiration(token) {
    try {
      const decoded = jwt.decode(token);
      if (!decoded || !decoded.exp) {
        return null;
      }
      return new Date(decoded.exp * 1000);
    } catch (error) {
      return null;
    }
  }

  // Generate token pair (access + refresh)
  generateTokenPair(user, clientId, scopes = []) {
    const accessToken = this.generateAccessToken(user, clientId, scopes);
    const refreshToken = this.generateRefreshToken(user, clientId, scopes);

    return {
      access_token: accessToken,
      refresh_token: refreshToken,
      token_type: "Bearer",
      expires_in: parseInt(process.env.JWT_ACCESS_EXPIRES_IN || "900"),
      scope: scopes.join(" "),
    };
  }

  // Generate OAuth2 token response
  generateOAuth2Response(
    user,
    clientId,
    scopes = [],
    includeIdToken = false,
    nonce = null
  ) {
    const tokenPair = this.generateTokenPair(user, clientId, scopes);

    const response = {
      access_token: tokenPair.access_token,
      token_type: tokenPair.token_type,
      expires_in: tokenPair.expires_in,
      refresh_token: tokenPair.refresh_token,
      scope: tokenPair.scope,
    };

    // Include ID token if requested (OpenID Connect)
    if (includeIdToken && scopes.includes("openid")) {
      response.id_token = this.generateIdToken(user, clientId, scopes, nonce);
    }

    return response;
  }
}

module.exports = new JWTService();
