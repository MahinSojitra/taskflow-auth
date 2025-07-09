const mongoose = require("mongoose");
const crypto = require("crypto");

const tokenSchema = new mongoose.Schema(
  {
    tokenType: {
      type: String,
      enum: ["access_token", "refresh_token", "authorization_code", "id_token"],
      required: true,
    },
    token: {
      type: String,
      required: true,
      unique: true,
      default: () => crypto.randomBytes(64).toString("hex"),
    },
    clientId: {
      type: String,
      required: true,
      ref: "Client",
    },
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: function () {
        return this.tokenType !== "client_credentials";
      },
    },
    scopes: [
      {
        type: String,
        enum: ["openid", "profile", "email", "read", "write", "admin"],
      },
    ],
    // OAuth2 specific fields
    authorizationCode: {
      type: String,
      required: function () {
        return (
          this.tokenType === "access_token" ||
          this.tokenType === "refresh_token"
        );
      },
    },
    redirectUri: String,
    // PKCE fields
    codeVerifier: String,
    codeChallenge: String,
    codeChallengeMethod: {
      type: String,
      enum: ["S256", "plain"],
    },
    // Token metadata
    issuedAt: {
      type: Date,
      default: Date.now,
    },
    expiresAt: {
      type: Date,
      required: true,
    },
    // Token rotation
    parentToken: {
      type: String,
      ref: "Token",
    },
    childTokens: [
      {
        type: String,
        ref: "Token",
      },
    ],
    // Security
    isRevoked: {
      type: Boolean,
      default: false,
    },
    revokedAt: Date,
    revokedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
    },
    revokedReason: String,
    // Audit
    ipAddress: String,
    userAgent: String,
    // JWT payload (for id tokens)
    jwtPayload: {
      type: Map,
      of: mongoose.Schema.Types.Mixed,
    },
  },
  {
    timestamps: true,
  }
);

// Indexes
tokenSchema.index({ token: 1 });
tokenSchema.index({ tokenType: 1 });
tokenSchema.index({ clientId: 1 });
tokenSchema.index({ userId: 1 });
tokenSchema.index({ expiresAt: 1 });
tokenSchema.index({ isRevoked: 1 });
tokenSchema.index({ authorizationCode: 1 });

// Virtual for token status
tokenSchema.virtual("isExpired").get(function () {
  return this.expiresAt < new Date();
});

tokenSchema.virtual("isValid").get(function () {
  return !this.isRevoked && !this.isExpired;
});

// Virtual for token age
tokenSchema.virtual("age").get(function () {
  return Date.now() - this.issuedAt.getTime();
});

// Instance method to check if token is valid
tokenSchema.methods.isValidToken = function () {
  return !this.isRevoked && !this.isExpired;
};

// Instance method to revoke token
tokenSchema.methods.revoke = function (userId, reason = "Manual revocation") {
  this.isRevoked = true;
  this.revokedAt = new Date();
  this.revokedBy = userId;
  this.revokedReason = reason;
  return this.save();
};

// Instance method to extend token
tokenSchema.methods.extend = function (additionalTime) {
  this.expiresAt = new Date(this.expiresAt.getTime() + additionalTime);
  return this.save();
};

// Static method to find valid token
tokenSchema.statics.findValidToken = function (token, tokenType) {
  return this.findOne({
    token,
    tokenType,
    isRevoked: false,
    expiresAt: { $gt: new Date() },
  });
};

// Static method to find by authorization code
tokenSchema.statics.findByAuthorizationCode = function (code) {
  return this.findOne({
    authorizationCode: code,
    tokenType: "authorization_code",
    isRevoked: false,
    expiresAt: { $gt: new Date() },
  });
};

// Static method to find all tokens for a user
tokenSchema.statics.findUserTokens = function (userId, tokenType = null) {
  const query = { userId, isRevoked: false };
  if (tokenType) {
    query.tokenType = tokenType;
  }
  return this.find(query);
};

// Static method to find all tokens for a client
tokenSchema.statics.findClientTokens = function (clientId, tokenType = null) {
  const query = { clientId, isRevoked: false };
  if (tokenType) {
    query.tokenType = tokenType;
  }
  return this.find(query);
};

// Static method to revoke all tokens for a user
tokenSchema.statics.revokeUserTokens = function (
  userId,
  reason = "User logout"
) {
  return this.updateMany(
    { userId, isRevoked: false },
    {
      isRevoked: true,
      revokedAt: new Date(),
      revokedReason: reason,
    }
  );
};

// Static method to revoke all tokens for a client
tokenSchema.statics.revokeClientTokens = function (
  clientId,
  reason = "Client revocation"
) {
  return this.updateMany(
    { clientId, isRevoked: false },
    {
      isRevoked: true,
      revokedAt: new Date(),
      revokedReason: reason,
    }
  );
};

// Static method to clean up expired tokens
tokenSchema.statics.cleanupExpired = function () {
  return this.deleteMany({
    expiresAt: { $lt: new Date() },
    isRevoked: true,
  });
};

// Static method to get token statistics
tokenSchema.statics.getStats = function () {
  return this.aggregate([
    {
      $group: {
        _id: "$tokenType",
        count: { $sum: 1 },
        activeCount: {
          $sum: {
            $cond: [
              {
                $and: [
                  { $eq: ["$isRevoked", false] },
                  { $gt: ["$expiresAt", new Date()] },
                ],
              },
              1,
              0,
            ],
          },
        },
      },
    },
  ]);
};

// Pre-save middleware to set expiration based on token type
tokenSchema.pre("save", function (next) {
  if (this.isModified("tokenType") || this.isNew) {
    let expirationTime;

    switch (this.tokenType) {
      case "access_token":
        expirationTime =
          parseInt(process.env.OAUTH2_ACCESS_TOKEN_EXPIRES_IN || "3600") * 1000; // 1 hour default
        break;
      case "refresh_token":
        expirationTime =
          parseInt(process.env.OAUTH2_REFRESH_TOKEN_EXPIRES_IN || "2592000") *
          1000; // 30 days default
        break;
      case "authorization_code":
        expirationTime =
          parseInt(process.env.OAUTH2_AUTHORIZATION_CODE_EXPIRES_IN || "600") *
          1000; // 10 minutes default
        break;
      case "id_token":
        expirationTime =
          parseInt(process.env.JWT_ID_EXPIRES_IN || "3600") * 1000; // 1 hour default
        break;
      default:
        expirationTime = 3600000; // 1 hour default
    }

    this.expiresAt = new Date(Date.now() + expirationTime);
  }
  next();
});

module.exports = mongoose.model("Token", tokenSchema);
