const User = require("../models/User");
const jwtService = require("../utils/jwt");
const logger = require("../utils/logger");
const crypto = require("crypto");

class AuthController {
  // User registration
  async register(req, res) {
    try {
      const { email, password, firstName, lastName, username } = req.body;

      // Check if user already exists
      const existingUser = await User.findOne({
        $or: [{ email }, { username }],
      });

      if (existingUser) {
        return res.status(409).json({
          error: "user_exists",
          error_description: "User with this email or username already exists",
        });
      }

      // Create new user
      const user = new User({
        email,
        password,
        firstName,
        lastName,
        username:
          username ||
          `${firstName.toLowerCase()}${lastName.toLowerCase()}${Date.now()}`,
      });

      await user.save();

      // Generate tokens for immediate login
      const tokenResponse = jwtService.generateTokenPair(user, "taskflow-auth");

      logger.info("User registered successfully", {
        userId: user._id,
        email: user.email,
      });

      res.status(201).json({
        message: "User registered successfully",
        user: {
          id: user._id,
          email: user.email,
          username: user.username,
          firstName: user.firstName,
          lastName: user.lastName,
          role: user.role,
          isEmailVerified: user.isEmailVerified,
        },
        ...tokenResponse,
      });
    } catch (error) {
      logger.error("User registration failed:", error);
      res.status(500).json({
        error: "registration_failed",
        error_description: "Failed to register user",
      });
    }
  }

  // User login
  async login(req, res) {
    try {
      const { identifier, password } = req.body;

      // Find user by email or username
      const user = await User.findByEmailOrUsername(identifier);
      if (!user) {
        return res.status(401).json({
          error: "invalid_credentials",
          error_description: "Invalid email/username or password",
        });
      }

      // Check if account is locked
      if (user.isLocked()) {
        return res.status(423).json({
          error: "account_locked",
          error_description:
            "Account is temporarily locked due to too many failed login attempts",
        });
      }

      // Verify password
      const isValidPassword = await user.comparePassword(password);
      if (!isValidPassword) {
        await user.incLoginAttempts();
        return res.status(401).json({
          error: "invalid_credentials",
          error_description: "Invalid email/username or password",
        });
      }

      // Reset login attempts on successful login
      await user.resetLoginAttempts();
      user.lastLogin = new Date();
      await user.save();

      // Generate tokens
      const tokenResponse = jwtService.generateTokenPair(user, "taskflow-auth");

      logger.info("User logged in successfully", {
        userId: user._id,
        email: user.email,
      });

      res.json({
        message: "Login successful",
        user: {
          id: user._id,
          email: user.email,
          username: user.username,
          firstName: user.firstName,
          lastName: user.lastName,
          role: user.role,
          isEmailVerified: user.isEmailVerified,
        },
        ...tokenResponse,
      });
    } catch (error) {
      logger.error("User login failed:", error);
      res.status(500).json({
        error: "login_failed",
        error_description: "Failed to authenticate user",
      });
    }
  }

  // Refresh token
  async refreshToken(req, res) {
    try {
      const { refresh_token } = req.body;

      if (!refresh_token) {
        return res.status(400).json({
          error: "invalid_request",
          error_description: "refresh_token is required",
        });
      }

      // Verify refresh token
      const decoded = jwtService.verifyRefreshToken(refresh_token);

      // Get user
      const user = await User.findById(decoded.sub);
      if (!user || !user.isActive) {
        return res.status(401).json({
          error: "invalid_token",
          error_description: "Invalid refresh token",
        });
      }

      // Generate new tokens
      const tokenResponse = jwtService.generateTokenPair(user, "taskflow-auth");

      logger.info("Token refreshed successfully", { userId: user._id });

      res.json({
        message: "Token refreshed successfully",
        ...tokenResponse,
      });
    } catch (error) {
      logger.error("Token refresh failed:", error);
      res.status(401).json({
        error: "invalid_token",
        error_description: "Invalid refresh token",
      });
    }
  }

  // Get current user profile
  async getProfile(req, res) {
    try {
      const user = await User.findById(req.user._id).select("-password");

      res.json({
        user: {
          id: user._id,
          email: user.email,
          username: user.username,
          firstName: user.firstName,
          lastName: user.lastName,
          role: user.role,
          isEmailVerified: user.isEmailVerified,
          profile: user.profile,
          preferences: user.preferences,
          createdAt: user.createdAt,
          lastLogin: user.lastLogin,
        },
      });
    } catch (error) {
      logger.error("Get profile failed:", error);
      res.status(500).json({
        error: "profile_fetch_failed",
        error_description: "Failed to fetch user profile",
      });
    }
  }

  // Update user profile
  async updateProfile(req, res) {
    try {
      const updates = req.body;
      const user = await User.findById(req.user._id);

      // Update allowed fields
      const allowedFields = [
        "firstName",
        "lastName",
        "username",
        "profile",
        "preferences",
      ];

      for (const field of allowedFields) {
        if (updates[field] !== undefined) {
          user[field] = updates[field];
        }
      }

      // Check username uniqueness if changed
      if (updates.username && updates.username !== user.username) {
        const existingUser = await User.findOne({ username: updates.username });
        if (existingUser) {
          return res.status(409).json({
            error: "username_exists",
            error_description: "Username already taken",
          });
        }
      }

      await user.save();

      logger.info("Profile updated successfully", { userId: user._id });

      res.json({
        message: "Profile updated successfully",
        user: {
          id: user._id,
          email: user.email,
          username: user.username,
          firstName: user.firstName,
          lastName: user.lastName,
          role: user.role,
          profile: user.profile,
          preferences: user.preferences,
        },
      });
    } catch (error) {
      logger.error("Profile update failed:", error);
      res.status(500).json({
        error: "profile_update_failed",
        error_description: "Failed to update profile",
      });
    }
  }

  // Change password
  async changePassword(req, res) {
    try {
      const { currentPassword, newPassword } = req.body;
      const user = await User.findById(req.user._id);

      // Verify current password
      const isValidPassword = await user.comparePassword(currentPassword);
      if (!isValidPassword) {
        return res.status(401).json({
          error: "invalid_password",
          error_description: "Current password is incorrect",
        });
      }

      // Update password
      user.password = newPassword;
      await user.save();

      logger.info("Password changed successfully", { userId: user._id });

      res.json({
        message: "Password changed successfully",
      });
    } catch (error) {
      logger.error("Password change failed:", error);
      res.status(500).json({
        error: "password_change_failed",
        error_description: "Failed to change password",
      });
    }
  }

  // Logout (revoke tokens)
  async logout(req, res) {
    try {
      const Token = require("../models/Token");

      // Revoke all tokens for the user
      await Token.revokeUserTokens(req.user._id, "User logout");

      logger.info("User logged out successfully", { userId: req.user._id });

      res.json({
        message: "Logged out successfully",
      });
    } catch (error) {
      logger.error("Logout failed:", error);
      res.status(500).json({
        error: "logout_failed",
        error_description: "Failed to logout",
      });
    }
  }

  // Request password reset
  async requestPasswordReset(req, res) {
    try {
      const { email } = req.body;

      const user = await User.findOne({ email });
      if (!user) {
        // Don't reveal if email exists or not
        return res.json({
          message: "If the email exists, a password reset link has been sent",
        });
      }

      // Generate reset token
      const resetToken = crypto.randomBytes(32).toString("hex");
      const resetExpires = new Date(Date.now() + 3600000); // 1 hour

      user.passwordResetToken = resetToken;
      user.passwordResetExpires = resetExpires;
      await user.save();

      // TODO: Send email with reset link
      // For now, just log the token
      logger.info("Password reset requested", {
        userId: user._id,
        email: user.email,
        resetToken,
      });

      res.json({
        message: "If the email exists, a password reset link has been sent",
      });
    } catch (error) {
      logger.error("Password reset request failed:", error);
      res.status(500).json({
        error: "reset_request_failed",
        error_description: "Failed to process password reset request",
      });
    }
  }

  // Reset password with token
  async resetPassword(req, res) {
    try {
      const { token, newPassword } = req.body;

      const user = await User.findOne({
        passwordResetToken: token,
        passwordResetExpires: { $gt: Date.now() },
      });

      if (!user) {
        return res.status(400).json({
          error: "invalid_token",
          error_description: "Invalid or expired reset token",
        });
      }

      // Update password and clear reset token
      user.password = newPassword;
      user.passwordResetToken = undefined;
      user.passwordResetExpires = undefined;
      await user.save();

      logger.info("Password reset successfully", { userId: user._id });

      res.json({
        message: "Password reset successfully",
      });
    } catch (error) {
      logger.error("Password reset failed:", error);
      res.status(500).json({
        error: "reset_failed",
        error_description: "Failed to reset password",
      });
    }
  }

  // Verify email
  async verifyEmail(req, res) {
    try {
      const { token } = req.params;

      const user = await User.findOne({
        emailVerificationToken: token,
        emailVerificationExpires: { $gt: Date.now() },
      });

      if (!user) {
        return res.status(400).json({
          error: "invalid_token",
          error_description: "Invalid or expired verification token",
        });
      }

      user.isEmailVerified = true;
      user.emailVerificationToken = undefined;
      user.emailVerificationExpires = undefined;
      await user.save();

      logger.info("Email verified successfully", { userId: user._id });

      res.json({
        message: "Email verified successfully",
      });
    } catch (error) {
      logger.error("Email verification failed:", error);
      res.status(500).json({
        error: "verification_failed",
        error_description: "Failed to verify email",
      });
    }
  }

  // Resend email verification
  async resendEmailVerification(req, res) {
    try {
      const user = await User.findById(req.user._id);

      if (user.isEmailVerified) {
        return res.status(400).json({
          error: "already_verified",
          error_description: "Email is already verified",
        });
      }

      // Generate new verification token
      const verificationToken = crypto.randomBytes(32).toString("hex");
      const verificationExpires = new Date(Date.now() + 86400000); // 24 hours

      user.emailVerificationToken = verificationToken;
      user.emailVerificationExpires = verificationExpires;
      await user.save();

      // TODO: Send verification email
      logger.info("Email verification resent", {
        userId: user._id,
        email: user.email,
        verificationToken,
      });

      res.json({
        message: "Verification email sent",
      });
    } catch (error) {
      logger.error("Resend verification failed:", error);
      res.status(500).json({
        error: "verification_resend_failed",
        error_description: "Failed to resend verification email",
      });
    }
  }
}

module.exports = new AuthController();
