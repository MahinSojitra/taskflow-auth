const http = require("http");
const app = require("./app");
const connectDB = require("./src/config/database");
const logger = require("./src/utils/logger");

const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || "localhost";

const startServer = async () => {
  try {
    await connectDB();
    logger.info("✅ Database Connected Successfully");

    const server = http.createServer(app);
    server.listen(PORT, () => {
      logger.info(`🚀 Server running on http://${HOST}:${PORT}`);
    });

    process.on("unhandledRejection", (err) => {
      logger.error("❌ Unhandled Rejection:", err.message);
      server.close(() => process.exit(1));
    });

    process.on("uncaughtException", (err) => {
      logger.error("❌ Uncaught Exception:", err.message);
      process.exit(1);
    });

    process.on("SIGTERM", () => {
      logger.info("SIGTERM received, shutting down gracefully");
      process.exit(0);
    });

    process.on("SIGINT", () => {
      logger.info("SIGINT received, shutting down gracefully");
      process.exit(0);
    });
  } catch (error) {
    logger.error("❌ Server failed to start:", error.message);
    process.exit(1);
  }
};

startServer();
