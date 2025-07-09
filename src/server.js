require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const compression = require("compression");
const rateLimit = require("express-rate-limit");
const slowDown = require("express-slow-down");
const mongoSanitize = require("express-mongo-sanitize");
const hpp = require("hpp");
const swaggerJsdoc = require("swagger-jsdoc");
const swaggerUi = require("swagger-ui-express");

const connectDB = require("./config/database");
const logger = require("./utils/logger");

// Import routes
const authRoutes = require("./routes/auth");
const oauth2Routes = require("./routes/oauth2");
const clientRoutes = require("./routes/clients");

// Initialize Express app
const app = express();

// Connect to MongoDB
connectDB();

// Swagger configuration
const swaggerOptions = {
  definition: {
    openapi: "3.0.0",
    info: {
      title: "TaskFlowAuth API",
      version: "1.0.0",
      description:
        "Production-ready OAuth 2.0 and OpenID Connect authentication API",
      contact: {
        name: "TaskFlowAuth Team",
        email: "support@taskflowauth.com",
      },
      license: {
        name: "MIT",
        url: "https://opensource.org/licenses/MIT",
      },
    },
    servers: [
      {
        url: process.env.HOST || "http://localhost:3000",
        description: "Development server",
      },
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: "http",
          scheme: "bearer",
          bearerFormat: "JWT",
        },
        basicAuth: {
          type: "http",
          scheme: "basic",
        },
      },
      schemas: {
        Error: {
          type: "object",
          properties: {
            error: {
              type: "string",
              description: "Error code",
            },
            error_description: {
              type: "string",
              description: "Error description",
            },
            details: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  field: { type: "string" },
                  message: { type: "string" },
                  value: { type: "string" },
                },
              },
            },
          },
        },
        User: {
          type: "object",
          properties: {
            id: { type: "string" },
            email: { type: "string", format: "email" },
            username: { type: "string" },
            firstName: { type: "string" },
            lastName: { type: "string" },
            role: { type: "string", enum: ["user", "admin", "moderator"] },
            isEmailVerified: { type: "boolean" },
            profile: {
              type: "object",
              properties: {
                avatar: { type: "string" },
                bio: { type: "string" },
                location: { type: "string" },
                website: { type: "string" },
                phone: { type: "string" },
              },
            },
            preferences: {
              type: "object",
              properties: {
                emailNotifications: { type: "boolean" },
                twoFactorEnabled: { type: "boolean" },
                language: { type: "string" },
                timezone: { type: "string" },
              },
            },
            createdAt: { type: "string", format: "date-time" },
            lastLogin: { type: "string", format: "date-time" },
          },
        },
        Client: {
          type: "object",
          properties: {
            id: { type: "string" },
            name: { type: "string" },
            clientId: { type: "string" },
            clientSecret: { type: "string" },
            clientType: { type: "string", enum: ["public", "confidential"] },
            redirectUris: {
              type: "array",
              items: { type: "string", format: "uri" },
            },
            scopes: {
              type: "array",
              items: {
                type: "string",
                enum: ["openid", "profile", "email", "read", "write", "admin"],
              },
            },
            grantTypes: {
              type: "array",
              items: {
                type: "string",
                enum: [
                  "authorization_code",
                  "client_credentials",
                  "refresh_token",
                  "password",
                ],
              },
            },
            responseTypes: {
              type: "array",
              items: { type: "string", enum: ["code", "token", "id_token"] },
            },
            requirePKCE: { type: "boolean" },
            isActive: { type: "boolean" },
            createdAt: { type: "string", format: "date-time" },
          },
        },
      },
    },
  },
  apis: ["./src/routes/*.js"],
};

const swaggerSpec = swaggerJsdoc(swaggerOptions);

// Security middleware
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        scriptSrc: ["'self'"],
        imgSrc: ["'self'", "data:", "https:"],
      },
    },
    crossOriginEmbedderPolicy: false,
  })
);

// CORS configuration
const corsOptions = {
  origin: process.env.CORS_ORIGIN
    ? process.env.CORS_ORIGIN.split(",")
    : ["http://localhost:3000"],
  credentials: process.env.CORS_CREDENTIALS === "true",
  optionsSuccessStatus: 200,
};
app.use(cors(corsOptions));

// Compression middleware
app.use(compression());

// Body parsing middleware
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));

// Security middleware
app.use(mongoSanitize()); // Prevent NoSQL injection
app.use(hpp()); // Prevent HTTP Parameter Pollution

// Rate limiting
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100, // limit each IP to 100 requests per windowMs
  message: {
    error: "rate_limit_exceeded",
    error_description:
      "Too many requests from this IP, please try again later.",
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Slow down middleware
const speedLimiter = slowDown({
  windowMs: parseInt(process.env.SLOW_DOWN_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
  delayAfter: parseInt(process.env.SLOW_DOWN_DELAY_AFTER) || 50, // allow 50 requests per 15 minutes, then...
  delayMs: (hits) => hits * 100, // begin adding 100ms of delay per request above 50
  maxDelayMs: parseInt(process.env.SLOW_DOWN_MAX_DELAY_MS) || 20000, // maximum delay of 20 seconds
});

// Apply rate limiting to all routes
app.use(limiter);
app.use(speedLimiter);

// Request logging middleware
app.use((req, res, next) => {
  logger.info(`${req.method} ${req.path}`, {
    ip: req.ip,
    userAgent: req.get("User-Agent"),
    timestamp: new Date().toISOString(),
  });
  next();
});

// Health check endpoint
app.get("/health", (req, res) => {
  res.status(200).json({
    status: "OK",
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: process.env.NODE_ENV || "development",
  });
});

// API documentation
app.use(
  "/api-docs",
  swaggerUi.serve,
  swaggerUi.setup(swaggerSpec, {
    customCss: ".swagger-ui .topbar { display: none }",
    customSiteTitle: "TaskFlowAuth API Documentation",
  })
);

// API routes
app.use("/auth", authRoutes);
app.use("/oauth2", oauth2Routes);
app.use("/clients", clientRoutes);

// Root endpoint
app.get("/", (req, res) => {
  res.json({
    message: "TaskFlowAuth API",
    version: "1.0.0",
    description:
      "Production-ready OAuth 2.0 and OpenID Connect authentication API",
    documentation: "/api-docs",
    health: "/health",
    endpoints: {
      auth: "/auth",
      oauth2: "/oauth2",
      clients: "/clients",
    },
  });
});

// 404 handler
app.use("*", (req, res) => {
  res.status(404).json({
    error: "not_found",
    error_description: "The requested resource was not found",
  });
});

// Global error handler
app.use((error, req, res, next) => {
  logger.error("Unhandled error:", error);

  // Mongoose validation error
  if (error.name === "ValidationError") {
    const errors = Object.values(error.errors).map((err) => ({
      field: err.path,
      message: err.message,
      value: err.value,
    }));

    return res.status(400).json({
      error: "validation_error",
      error_description: "Validation failed",
      details: errors,
    });
  }

  // Mongoose duplicate key error
  if (error.code === 11000) {
    const field = Object.keys(error.keyValue)[0];
    return res.status(409).json({
      error: "duplicate_key",
      error_description: `${field} already exists`,
    });
  }

  // JWT errors
  if (error.name === "JsonWebTokenError") {
    return res.status(401).json({
      error: "invalid_token",
      error_description: "Invalid token",
    });
  }

  if (error.name === "TokenExpiredError") {
    return res.status(401).json({
      error: "token_expired",
      error_description: "Token has expired",
    });
  }

  // Default error response
  res.status(error.status || 500).json({
    error: "internal_server_error",
    error_description:
      process.env.NODE_ENV === "production"
        ? "An internal server error occurred"
        : error.message,
  });
});

// Graceful shutdown
process.on("SIGTERM", () => {
  logger.info("SIGTERM received, shutting down gracefully");
  process.exit(0);
});

process.on("SIGINT", () => {
  logger.info("SIGINT received, shutting down gracefully");
  process.exit(0);
});

// Unhandled promise rejection handler
process.on("unhandledRejection", (reason, promise) => {
  logger.error("Unhandled Rejection at:", promise, "reason:", reason);
  process.exit(1);
});

// Uncaught exception handler
process.on("uncaughtException", (error) => {
  logger.error("Uncaught Exception:", error);
  process.exit(1);
});

// Start server
const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || "localhost";

app.listen(PORT, () => {
  logger.info(`TaskFlowAuth server running on http://${HOST}:${PORT}`);
  logger.info(`API Documentation available at http://${HOST}:${PORT}/api-docs`);
  logger.info(`Environment: ${process.env.NODE_ENV || "development"}`);
});

module.exports = app;
