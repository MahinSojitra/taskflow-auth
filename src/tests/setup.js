require("dotenv").config({ path: ".env.test" });

const mongoose = require("mongoose");

// Set test environment
process.env.NODE_ENV = "test";

// Connect to test database
beforeAll(async () => {
  const mongoURI =
    process.env.MONGODB_URI_TEST ||
    "mongodb://localhost:27017/taskflow_auth_test";
  await mongoose.connect(mongoURI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  });
});

// Clear database after each test
afterEach(async () => {
  const collections = mongoose.connection.collections;
  for (const key in collections) {
    const collection = collections[key];
    await collection.deleteMany();
  }
});

// Close database connection after all tests
afterAll(async () => {
  await mongoose.connection.close();
});

// Mock console methods to reduce noise in tests
global.console = {
  ...console,
  log: jest.fn(),
  debug: jest.fn(),
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
};
