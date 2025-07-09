const { body, query, param, validationResult } = require("express-validator");

// Handle validation errors
const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    const errorMessages = errors.array().map((error) => ({
      field: error.path,
      message: error.msg,
      value: error.value,
    }));

    return res.status(400).json({
      error: "validation_error",
      error_description: "Validation failed",
      details: errorMessages,
    });
  }
  next();
};

// User registration validation
const validateUserRegistration = [
  body("email")
    .isEmail()
    .normalizeEmail()
    .withMessage("Please provide a valid email address"),

  body("password")
    .isLength({ min: 8 })
    .withMessage("Password must be at least 8 characters long")
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .withMessage(
      "Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character"
    ),

  body("firstName")
    .trim()
    .isLength({ min: 1, max: 50 })
    .withMessage("First name must be between 1 and 50 characters"),

  body("lastName")
    .trim()
    .isLength({ min: 1, max: 50 })
    .withMessage("Last name must be between 1 and 50 characters"),

  body("username")
    .optional()
    .trim()
    .isLength({ min: 3, max: 30 })
    .withMessage("Username must be between 3 and 30 characters")
    .matches(/^[a-zA-Z0-9_]+$/)
    .withMessage("Username can only contain letters, numbers, and underscores"),

  handleValidationErrors,
];

// User login validation
const validateUserLogin = [
  body("identifier")
    .trim()
    .notEmpty()
    .withMessage("Email or username is required"),

  body("password").notEmpty().withMessage("Password is required"),

  handleValidationErrors,
];

// OAuth2 authorization request validation
const validateOAuth2Authorization = [
  query("response_type")
    .isIn(["code", "token", "id_token"])
    .withMessage("Invalid response_type"),

  query("client_id").notEmpty().withMessage("client_id is required"),

  query("redirect_uri").isURL().withMessage("Invalid redirect_uri"),

  query("scope").optional().isString().withMessage("scope must be a string"),

  query("state").optional().isString().withMessage("state must be a string"),

  query("nonce").optional().isString().withMessage("nonce must be a string"),

  query("code_challenge")
    .optional()
    .isString()
    .withMessage("code_challenge must be a string"),

  query("code_challenge_method")
    .optional()
    .isIn(["S256", "plain"])
    .withMessage("code_challenge_method must be S256 or plain"),

  handleValidationErrors,
];

// OAuth2 token request validation
const validateOAuth2Token = [
  body("grant_type")
    .isIn([
      "authorization_code",
      "refresh_token",
      "client_credentials",
      "password",
    ])
    .withMessage("Invalid grant_type"),

  body("client_id").notEmpty().withMessage("client_id is required"),

  body("client_secret")
    .optional()
    .isString()
    .withMessage("client_secret must be a string"),

  body("code")
    .if(body("grant_type").equals("authorization_code"))
    .notEmpty()
    .withMessage("code is required for authorization_code grant type"),

  body("redirect_uri")
    .if(body("grant_type").equals("authorization_code"))
    .isURL()
    .withMessage("Invalid redirect_uri"),

  body("refresh_token")
    .if(body("grant_type").equals("refresh_token"))
    .notEmpty()
    .withMessage("refresh_token is required for refresh_token grant type"),

  body("username")
    .if(body("grant_type").equals("password"))
    .notEmpty()
    .withMessage("username is required for password grant type"),

  body("password")
    .if(body("grant_type").equals("password"))
    .notEmpty()
    .withMessage("password is required for password grant type"),

  body("scope").optional().isString().withMessage("scope must be a string"),

  body("code_verifier")
    .optional()
    .isString()
    .withMessage("code_verifier must be a string"),

  handleValidationErrors,
];

// Client registration validation
const validateClientRegistration = [
  body("name")
    .trim()
    .isLength({ min: 1, max: 100 })
    .withMessage("Client name must be between 1 and 100 characters"),

  body("description")
    .optional()
    .trim()
    .isLength({ max: 500 })
    .withMessage("Description cannot exceed 500 characters"),

  body("clientType")
    .isIn(["public", "confidential"])
    .withMessage("clientType must be public or confidential"),

  body("redirectUris")
    .isArray({ min: 1 })
    .withMessage("At least one redirect URI is required"),

  body("redirectUris.*").isURL().withMessage("Invalid redirect URI format"),

  body("scopes").optional().isArray().withMessage("scopes must be an array"),

  body("scopes.*")
    .optional()
    .isIn(["openid", "profile", "email", "read", "write", "admin"])
    .withMessage("Invalid scope"),

  body("grantTypes")
    .optional()
    .isArray()
    .withMessage("grantTypes must be an array"),

  body("grantTypes.*")
    .optional()
    .isIn([
      "authorization_code",
      "client_credentials",
      "refresh_token",
      "password",
    ])
    .withMessage("Invalid grant type"),

  body("responseTypes")
    .optional()
    .isArray()
    .withMessage("responseTypes must be an array"),

  body("responseTypes.*")
    .optional()
    .isIn(["code", "token", "id_token"])
    .withMessage("Invalid response type"),

  body("requirePKCE")
    .optional()
    .isBoolean()
    .withMessage("requirePKCE must be a boolean"),

  body("codeChallengeMethods")
    .optional()
    .isArray()
    .withMessage("codeChallengeMethods must be an array"),

  body("codeChallengeMethods.*")
    .optional()
    .isIn(["S256", "plain"])
    .withMessage("Invalid code challenge method"),

  body("allowedOrigins")
    .optional()
    .isArray()
    .withMessage("allowedOrigins must be an array"),

  body("allowedOrigins.*")
    .optional()
    .isURL()
    .withMessage("Invalid origin format"),

  body("website").optional().isURL().withMessage("Invalid website URL"),

  body("privacyPolicy")
    .optional()
    .isURL()
    .withMessage("Invalid privacy policy URL"),

  body("termsOfService")
    .optional()
    .isURL()
    .withMessage("Invalid terms of service URL"),

  handleValidationErrors,
];

// User profile update validation
const validateUserProfileUpdate = [
  body("firstName")
    .optional()
    .trim()
    .isLength({ min: 1, max: 50 })
    .withMessage("First name must be between 1 and 50 characters"),

  body("lastName")
    .optional()
    .trim()
    .isLength({ min: 1, max: 50 })
    .withMessage("Last name must be between 1 and 50 characters"),

  body("username")
    .optional()
    .trim()
    .isLength({ min: 3, max: 30 })
    .withMessage("Username must be between 3 and 30 characters")
    .matches(/^[a-zA-Z0-9_]+$/)
    .withMessage("Username can only contain letters, numbers, and underscores"),

  body("profile.bio")
    .optional()
    .trim()
    .isLength({ max: 500 })
    .withMessage("Bio cannot exceed 500 characters"),

  body("profile.website").optional().isURL().withMessage("Invalid website URL"),

  body("profile.phone")
    .optional()
    .matches(/^\+?[\d\s\-\(\)]+$/)
    .withMessage("Invalid phone number format"),

  body("preferences.emailNotifications")
    .optional()
    .isBoolean()
    .withMessage("emailNotifications must be a boolean"),

  body("preferences.language")
    .optional()
    .isIn(["en", "es", "fr", "de", "zh", "ja", "ko"])
    .withMessage("Unsupported language"),

  body("preferences.timezone")
    .optional()
    .isString()
    .withMessage("timezone must be a string"),

  handleValidationErrors,
];

// Password change validation
const validatePasswordChange = [
  body("currentPassword")
    .notEmpty()
    .withMessage("Current password is required"),

  body("newPassword")
    .isLength({ min: 8 })
    .withMessage("New password must be at least 8 characters long")
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .withMessage(
      "New password must contain at least one uppercase letter, one lowercase letter, one number, and one special character"
    ),

  body("confirmPassword").custom((value, { req }) => {
    if (value !== req.body.newPassword) {
      throw new Error("Password confirmation does not match");
    }
    return true;
  }),

  handleValidationErrors,
];

// Token revocation validation
const validateTokenRevocation = [
  body("token").notEmpty().withMessage("Token is required"),

  body("token_type_hint")
    .optional()
    .isIn(["access_token", "refresh_token"])
    .withMessage("Invalid token_type_hint"),

  handleValidationErrors,
];

// Pagination validation
const validatePagination = [
  query("page")
    .optional()
    .isInt({ min: 1 })
    .withMessage("Page must be a positive integer"),

  query("limit")
    .optional()
    .isInt({ min: 1, max: 100 })
    .withMessage("Limit must be between 1 and 100"),

  query("sort").optional().isString().withMessage("Sort must be a string"),

  query("order")
    .optional()
    .isIn(["asc", "desc"])
    .withMessage("Order must be asc or desc"),

  handleValidationErrors,
];

// ID parameter validation
const validateId = [
  param("id").isMongoId().withMessage("Invalid ID format"),

  handleValidationErrors,
];

// Search validation
const validateSearch = [
  query("q")
    .optional()
    .trim()
    .isLength({ min: 1, max: 100 })
    .withMessage("Search query must be between 1 and 100 characters"),

  query("type")
    .optional()
    .isIn(["user", "client", "token"])
    .withMessage("Invalid search type"),

  handleValidationErrors,
];

module.exports = {
  handleValidationErrors,
  validateUserRegistration,
  validateUserLogin,
  validateOAuth2Authorization,
  validateOAuth2Token,
  validateClientRegistration,
  validateUserProfileUpdate,
  validatePasswordChange,
  validateTokenRevocation,
  validatePagination,
  validateId,
  validateSearch,
};
