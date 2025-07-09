const request = require("supertest");
const app = require("../server");
const User = require("../models/User");
const jwtService = require("../utils/jwt");

describe("Authentication API", () => {
  describe("POST /auth/register", () => {
    it("should register a new user successfully", async () => {
      const userData = {
        email: "test@example.com",
        password: "TestPass123!",
        firstName: "John",
        lastName: "Doe",
        username: "johndoe",
      };

      const response = await request(app)
        .post("/auth/register")
        .send(userData)
        .expect(201);

      expect(response.body).toHaveProperty(
        "message",
        "User registered successfully"
      );
      expect(response.body).toHaveProperty("user");
      expect(response.body).toHaveProperty("access_token");
      expect(response.body).toHaveProperty("refresh_token");
      expect(response.body.user.email).toBe(userData.email);
      expect(response.body.user.username).toBe(userData.username);
    });

    it("should return error for duplicate email", async () => {
      const userData = {
        email: "duplicate@example.com",
        password: "TestPass123!",
        firstName: "John",
        lastName: "Doe",
      };

      // Register first user
      await request(app).post("/auth/register").send(userData).expect(201);

      // Try to register with same email
      const response = await request(app)
        .post("/auth/register")
        .send(userData)
        .expect(409);

      expect(response.body.error).toBe("user_exists");
    });

    it("should return error for invalid email format", async () => {
      const userData = {
        email: "invalid-email",
        password: "TestPass123!",
        firstName: "John",
        lastName: "Doe",
      };

      const response = await request(app)
        .post("/auth/register")
        .send(userData)
        .expect(400);

      expect(response.body.error).toBe("validation_error");
    });

    it("should return error for weak password", async () => {
      const userData = {
        email: "test@example.com",
        password: "weak",
        firstName: "John",
        lastName: "Doe",
      };

      const response = await request(app)
        .post("/auth/register")
        .send(userData)
        .expect(400);

      expect(response.body.error).toBe("validation_error");
    });
  });

  describe("POST /auth/login", () => {
    beforeEach(async () => {
      const userData = {
        email: "login@example.com",
        password: "TestPass123!",
        firstName: "John",
        lastName: "Doe",
      };

      await request(app).post("/auth/register").send(userData);
    });

    it("should login user with email successfully", async () => {
      const loginData = {
        identifier: "login@example.com",
        password: "TestPass123!",
      };

      const response = await request(app)
        .post("/auth/login")
        .send(loginData)
        .expect(200);

      expect(response.body).toHaveProperty("message", "Login successful");
      expect(response.body).toHaveProperty("access_token");
      expect(response.body).toHaveProperty("refresh_token");
      expect(response.body.user.email).toBe(loginData.identifier);
    });

    it("should login user with username successfully", async () => {
      const loginData = {
        identifier: "johndoe",
        password: "TestPass123!",
      };

      const response = await request(app)
        .post("/auth/login")
        .send(loginData)
        .expect(200);

      expect(response.body).toHaveProperty("message", "Login successful");
    });

    it("should return error for invalid credentials", async () => {
      const loginData = {
        identifier: "login@example.com",
        password: "wrongpassword",
      };

      const response = await request(app)
        .post("/auth/login")
        .send(loginData)
        .expect(401);

      expect(response.body.error).toBe("invalid_credentials");
    });

    it("should return error for non-existent user", async () => {
      const loginData = {
        identifier: "nonexistent@example.com",
        password: "TestPass123!",
      };

      const response = await request(app)
        .post("/auth/login")
        .send(loginData)
        .expect(401);

      expect(response.body.error).toBe("invalid_credentials");
    });
  });

  describe("POST /auth/refresh", () => {
    let refreshToken;

    beforeEach(async () => {
      const userData = {
        email: "refresh@example.com",
        password: "TestPass123!",
        firstName: "John",
        lastName: "Doe",
      };

      const response = await request(app).post("/auth/register").send(userData);

      refreshToken = response.body.refresh_token;
    });

    it("should refresh token successfully", async () => {
      const response = await request(app)
        .post("/auth/refresh")
        .send({ refresh_token: refreshToken })
        .expect(200);

      expect(response.body).toHaveProperty(
        "message",
        "Token refreshed successfully"
      );
      expect(response.body).toHaveProperty("access_token");
      expect(response.body).toHaveProperty("refresh_token");
    });

    it("should return error for invalid refresh token", async () => {
      const response = await request(app)
        .post("/auth/refresh")
        .send({ refresh_token: "invalid-token" })
        .expect(401);

      expect(response.body.error).toBe("invalid_token");
    });

    it("should return error for missing refresh token", async () => {
      const response = await request(app)
        .post("/auth/refresh")
        .send({})
        .expect(400);

      expect(response.body.error).toBe("invalid_request");
    });
  });

  describe("GET /auth/profile", () => {
    let accessToken;

    beforeEach(async () => {
      const userData = {
        email: "profile@example.com",
        password: "TestPass123!",
        firstName: "John",
        lastName: "Doe",
      };

      const response = await request(app).post("/auth/register").send(userData);

      accessToken = response.body.access_token;
    });

    it("should get user profile successfully", async () => {
      const response = await request(app)
        .get("/auth/profile")
        .set("Authorization", `Bearer ${accessToken}`)
        .expect(200);

      expect(response.body).toHaveProperty("user");
      expect(response.body.user.email).toBe("profile@example.com");
      expect(response.body.user.firstName).toBe("John");
      expect(response.body.user.lastName).toBe("Doe");
    });

    it("should return error for missing token", async () => {
      const response = await request(app).get("/auth/profile").expect(401);

      expect(response.body.error).toBe("access_denied");
    });

    it("should return error for invalid token", async () => {
      const response = await request(app)
        .get("/auth/profile")
        .set("Authorization", "Bearer invalid-token")
        .expect(401);

      expect(response.body.error).toBe("invalid_token");
    });
  });

  describe("PUT /auth/profile", () => {
    let accessToken;

    beforeEach(async () => {
      const userData = {
        email: "update@example.com",
        password: "TestPass123!",
        firstName: "John",
        lastName: "Doe",
      };

      const response = await request(app).post("/auth/register").send(userData);

      accessToken = response.body.access_token;
    });

    it("should update user profile successfully", async () => {
      const updateData = {
        firstName: "Jane",
        lastName: "Smith",
        profile: {
          bio: "Updated bio",
          website: "https://example.com",
        },
      };

      const response = await request(app)
        .put("/auth/profile")
        .set("Authorization", `Bearer ${accessToken}`)
        .send(updateData)
        .expect(200);

      expect(response.body).toHaveProperty(
        "message",
        "Profile updated successfully"
      );
      expect(response.body.user.firstName).toBe("Jane");
      expect(response.body.user.lastName).toBe("Smith");
      expect(response.body.user.profile.bio).toBe("Updated bio");
    });

    it("should return error for duplicate username", async () => {
      // Create another user
      await request(app).post("/auth/register").send({
        email: "another@example.com",
        password: "TestPass123!",
        firstName: "Another",
        lastName: "User",
        username: "anotheruser",
      });

      const updateData = {
        username: "anotheruser",
      };

      const response = await request(app)
        .put("/auth/profile")
        .set("Authorization", `Bearer ${accessToken}`)
        .send(updateData)
        .expect(409);

      expect(response.body.error).toBe("username_exists");
    });
  });

  describe("POST /auth/change-password", () => {
    let accessToken;

    beforeEach(async () => {
      const userData = {
        email: "password@example.com",
        password: "TestPass123!",
        firstName: "John",
        lastName: "Doe",
      };

      const response = await request(app).post("/auth/register").send(userData);

      accessToken = response.body.access_token;
    });

    it("should change password successfully", async () => {
      const passwordData = {
        currentPassword: "TestPass123!",
        newPassword: "NewPass456!",
        confirmPassword: "NewPass456!",
      };

      const response = await request(app)
        .post("/auth/change-password")
        .set("Authorization", `Bearer ${accessToken}`)
        .send(passwordData)
        .expect(200);

      expect(response.body).toHaveProperty(
        "message",
        "Password changed successfully"
      );
    });

    it("should return error for incorrect current password", async () => {
      const passwordData = {
        currentPassword: "WrongPass123!",
        newPassword: "NewPass456!",
        confirmPassword: "NewPass456!",
      };

      const response = await request(app)
        .post("/auth/change-password")
        .set("Authorization", `Bearer ${accessToken}`)
        .send(passwordData)
        .expect(401);

      expect(response.body.error).toBe("invalid_password");
    });

    it("should return error for password mismatch", async () => {
      const passwordData = {
        currentPassword: "TestPass123!",
        newPassword: "NewPass456!",
        confirmPassword: "DifferentPass789!",
      };

      const response = await request(app)
        .post("/auth/change-password")
        .set("Authorization", `Bearer ${accessToken}`)
        .send(passwordData)
        .expect(400);

      expect(response.body.error).toBe("validation_error");
    });
  });

  describe("POST /auth/logout", () => {
    let accessToken;

    beforeEach(async () => {
      const userData = {
        email: "logout@example.com",
        password: "TestPass123!",
        firstName: "John",
        lastName: "Doe",
      };

      const response = await request(app).post("/auth/register").send(userData);

      accessToken = response.body.access_token;
    });

    it("should logout user successfully", async () => {
      const response = await request(app)
        .post("/auth/logout")
        .set("Authorization", `Bearer ${accessToken}`)
        .expect(200);

      expect(response.body).toHaveProperty(
        "message",
        "Logged out successfully"
      );
    });
  });
});
