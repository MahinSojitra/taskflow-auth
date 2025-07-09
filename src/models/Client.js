const mongoose = require("mongoose");
const crypto = require("crypto");

const clientSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true,
      maxlength: [100, "Client name cannot exceed 100 characters"],
    },
    description: {
      type: String,
      trim: true,
      maxlength: [500, "Description cannot exceed 500 characters"],
    },
    clientId: {
      type: String,
      required: true,
      unique: true,
      default: () => crypto.randomBytes(32).toString("hex"),
    },
    clientSecret: {
      type: String,
      required: true,
      default: () => crypto.randomBytes(64).toString("hex"),
    },
    clientType: {
      type: String,
      enum: ["public", "confidential"],
      required: true,
    },
    redirectUris: [
      {
        type: String,
        required: true,
        validate: {
          validator: function (uri) {
            // Basic URI validation
            try {
              new URL(uri);
              return true;
            } catch (e) {
              return false;
            }
          },
          message: "Invalid redirect URI format",
        },
      },
    ],
    scopes: [
      {
        type: String,
        enum: ["openid", "profile", "email", "read", "write", "admin"],
        default: ["openid", "profile", "email"],
      },
    ],
    grantTypes: [
      {
        type: String,
        enum: [
          "authorization_code",
          "client_credentials",
          "refresh_token",
          "password",
        ],
        default: ["authorization_code", "refresh_token"],
      },
    ],
    responseTypes: [
      {
        type: String,
        enum: ["code", "token", "id_token"],
        default: ["code"],
      },
    ],
    tokenEndpointAuthMethod: {
      type: String,
      enum: ["client_secret_basic", "client_secret_post", "none"],
      default: "client_secret_basic",
    },
    // PKCE support
    requirePKCE: {
      type: Boolean,
      default: false,
    },
    codeChallengeMethods: [
      {
        type: String,
        enum: ["S256", "plain"],
        default: ["S256"],
      },
    ],
    // Security settings
    allowedOrigins: [
      {
        type: String,
        validate: {
          validator: function (origin) {
            try {
              new URL(origin);
              return true;
            } catch (e) {
              return false;
            }
          },
          message: "Invalid origin format",
        },
      },
    ],
    // Rate limiting per client
    rateLimit: {
      requestsPerMinute: {
        type: Number,
        default: 100,
      },
      requestsPerHour: {
        type: Number,
        default: 1000,
      },
    },
    // Client status
    isActive: {
      type: Boolean,
      default: true,
    },
    isTrusted: {
      type: Boolean,
      default: false,
    },
    // Metadata
    website: String,
    logo: String,
    privacyPolicy: String,
    termsOfService: String,
    // Owner information
    owner: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    // Audit fields
    lastUsed: Date,
    usageCount: {
      type: Number,
      default: 0,
    },
  },
  {
    timestamps: true,
  }
);

// Indexes
clientSchema.index({ clientId: 1 });
clientSchema.index({ owner: 1 });
clientSchema.index({ isActive: 1 });
clientSchema.index({ redirectUris: 1 });

// Virtual for client type display
clientSchema.virtual("isPublic").get(function () {
  return this.clientType === "public";
});

// Instance method to validate redirect URI
clientSchema.methods.isValidRedirectUri = function (uri) {
  return this.redirectUris.includes(uri);
};

// Instance method to validate scope
clientSchema.methods.hasScope = function (scope) {
  return this.scopes.includes(scope);
};

// Instance method to validate grant type
clientSchema.methods.supportsGrantType = function (grantType) {
  return this.grantTypes.includes(grantType);
};

// Instance method to validate response type
clientSchema.methods.supportsResponseType = function (responseType) {
  return this.responseTypes.includes(responseType);
};

// Instance method to validate code challenge method
clientSchema.methods.supportsCodeChallengeMethod = function (method) {
  return this.codeChallengeMethods.includes(method);
};

// Instance method to check if PKCE is required
clientSchema.methods.requiresPKCE = function () {
  return this.requirePKCE || this.clientType === "public";
};

// Static method to find by client ID
clientSchema.statics.findByClientId = function (clientId) {
  return this.findOne({ clientId, isActive: true });
};

// Static method to validate client credentials
clientSchema.statics.validateCredentials = function (clientId, clientSecret) {
  return this.findOne({
    clientId,
    clientSecret,
    isActive: true,
  });
};

// Pre-save middleware to ensure public clients don't have client secret
clientSchema.pre("save", function (next) {
  if (this.clientType === "public" && this.clientSecret) {
    this.clientSecret = undefined;
  }
  next();
});

// Method to regenerate client secret
clientSchema.methods.regenerateClientSecret = function () {
  this.clientSecret = crypto.randomBytes(64).toString("hex");
  return this.save();
};

// Method to increment usage count
clientSchema.methods.incrementUsage = function () {
  this.usageCount += 1;
  this.lastUsed = new Date();
  return this.save();
};

module.exports = mongoose.model("Client", clientSchema);
