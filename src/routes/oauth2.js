const express = require("express");
const router = express.Router();
const oauth2Controller = require("../controllers/oauth2Controller");
const {
  verifyToken,
  authenticateClient,
  optionalAuth,
} = require("../middleware/auth");
const {
  validateOAuth2Authorization,
  validateOAuth2Token,
  validateTokenRevocation,
} = require("../middleware/validation");

/**
 * @swagger
 * /oauth2/authorize:
 *   get:
 *     summary: OAuth2 Authorization endpoint
 *     tags: [OAuth2]
 *     parameters:
 *       - in: query
 *         name: response_type
 *         required: true
 *         schema:
 *           type: string
 *           enum: [code, token, id_token]
 *       - in: query
 *         name: client_id
 *         required: true
 *         schema:
 *           type: string
 *       - in: query
 *         name: redirect_uri
 *         required: true
 *         schema:
 *           type: string
 *           format: uri
 *       - in: query
 *         name: scope
 *         schema:
 *           type: string
 *       - in: query
 *         name: state
 *         schema:
 *           type: string
 *       - in: query
 *         name: nonce
 *         schema:
 *           type: string
 *       - in: query
 *         name: code_challenge
 *         schema:
 *           type: string
 *       - in: query
 *         name: code_challenge_method
 *         schema:
 *           type: string
 *           enum: [S256, plain]
 *     responses:
 *       302:
 *         description: Redirect to client with authorization code
 *       400:
 *         description: Invalid request parameters
 */
router.get(
  "/authorize",
  validateOAuth2Authorization,
  optionalAuth,
  oauth2Controller.authorize
);

/**
 * @swagger
 * /oauth2/token:
 *   post:
 *     summary: OAuth2 Token endpoint
 *     tags: [OAuth2]
 *     requestBody:
 *       required: true
 *       content:
 *         application/x-www-form-urlencoded:
 *           schema:
 *             type: object
 *             required:
 *               - grant_type
 *               - client_id
 *             properties:
 *               grant_type:
 *                 type: string
 *                 enum: [authorization_code, refresh_token, client_credentials, password]
 *               client_id:
 *                 type: string
 *               client_secret:
 *                 type: string
 *               code:
 *                 type: string
 *               redirect_uri:
 *                 type: string
 *                 format: uri
 *               refresh_token:
 *                 type: string
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *               scope:
 *                 type: string
 *               code_verifier:
 *                 type: string
 *     responses:
 *       200:
 *         description: Token issued successfully
 *       400:
 *         description: Invalid request
 *       401:
 *         description: Invalid client credentials
 */
router.post(
  "/token",
  validateOAuth2Token,
  authenticateClient,
  oauth2Controller.token
);

/**
 * @swagger
 * /oauth2/userinfo:
 *   get:
 *     summary: OAuth2 UserInfo endpoint (OpenID Connect)
 *     tags: [OAuth2]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: User information retrieved successfully
 *       401:
 *         description: Invalid access token
 */
router.get("/userinfo", oauth2Controller.userinfo);

/**
 * @swagger
 * /oauth2/revoke:
 *   post:
 *     summary: OAuth2 Token Revocation endpoint
 *     tags: [OAuth2]
 *     requestBody:
 *       required: true
 *       content:
 *         application/x-www-form-urlencoded:
 *           schema:
 *             type: object
 *             required:
 *               - token
 *             properties:
 *               token:
 *                 type: string
 *               token_type_hint:
 *                 type: string
 *                 enum: [access_token, refresh_token]
 *     responses:
 *       200:
 *         description: Token revoked successfully
 *       400:
 *         description: Invalid request
 *       401:
 *         description: Invalid client credentials
 */
router.post(
  "/revoke",
  validateTokenRevocation,
  authenticateClient,
  oauth2Controller.revoke
);

/**
 * @swagger
 * /oauth2/introspect:
 *   post:
 *     summary: OAuth2 Token Introspection endpoint (RFC 7662)
 *     tags: [OAuth2]
 *     requestBody:
 *       required: true
 *       content:
 *         application/x-www-form-urlencoded:
 *           schema:
 *             type: object
 *             required:
 *               - token
 *             properties:
 *               token:
 *                 type: string
 *               token_type_hint:
 *                 type: string
 *                 enum: [access_token, refresh_token]
 *     responses:
 *       200:
 *         description: Token introspection successful
 *       400:
 *         description: Invalid request
 *       401:
 *         description: Invalid client credentials
 */
router.post("/introspect", authenticateClient, oauth2Controller.introspect);

/**
 * @swagger
 * /.well-known/openid_configuration:
 *   get:
 *     summary: OpenID Connect Discovery endpoint
 *     tags: [OAuth2]
 *     responses:
 *       200:
 *         description: OpenID Connect configuration
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 issuer:
 *                   type: string
 *                 authorization_endpoint:
 *                   type: string
 *                 token_endpoint:
 *                   type: string
 *                 userinfo_endpoint:
 *                   type: string
 *                 revocation_endpoint:
 *                   type: string
 *                 introspection_endpoint:
 *                   type: string
 *                 jwks_uri:
 *                   type: string
 *                 scopes_supported:
 *                   type: array
 *                   items:
 *                     type: string
 *                 response_types_supported:
 *                   type: array
 *                   items:
 *                     type: string
 *                 grant_types_supported:
 *                   type: array
 *                   items:
 *                     type: string
 *                 token_endpoint_auth_methods_supported:
 *                   type: array
 *                   items:
 *                     type: string
 *                 subject_types_supported:
 *                   type: array
 *                   items:
 *                     type: string
 *                 id_token_signing_alg_values_supported:
 *                   type: array
 *                   items:
 *                     type: string
 *                 claims_supported:
 *                   type: array
 *                   items:
 *                     type: string
 *                 code_challenge_methods_supported:
 *                   type: array
 *                   items:
 *                     type: string
 */
router.get("/.well-known/openid_configuration", oauth2Controller.discovery);

/**
 * @swagger
 * /oauth2/jwks:
 *   get:
 *     summary: JSON Web Key Set endpoint
 *     tags: [OAuth2]
 *     responses:
 *       200:
 *         description: JSON Web Key Set
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 keys:
 *                   type: array
 *                   items:
 *                     type: object
 */
router.get("/jwks", oauth2Controller.jwks);

/**
 * @swagger
 * /oauth2/consent:
 *   post:
 *     summary: OAuth2 Consent endpoint
 *     tags: [OAuth2]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - approve
 *               - client_id
 *             properties:
 *               approve:
 *                 type: boolean
 *               client_id:
 *                 type: string
 *               scope:
 *                 type: string
 *               state:
 *                 type: string
 *     responses:
 *       302:
 *         description: Redirect to client
 *       400:
 *         description: Invalid request
 *       401:
 *         description: Unauthorized
 */
router.post("/consent", verifyToken, oauth2Controller.consent);

/**
 * @swagger
 * /oauth2/logout:
 *   get:
 *     summary: OpenID Connect Logout endpoint
 *     tags: [OAuth2]
 *     parameters:
 *       - in: query
 *         name: id_token_hint
 *         schema:
 *           type: string
 *       - in: query
 *         name: post_logout_redirect_uri
 *         schema:
 *           type: string
 *           format: uri
 *       - in: query
 *         name: state
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Logged out successfully
 *       302:
 *         description: Redirect to post-logout URI
 *       400:
 *         description: Invalid request
 */
router.get("/logout", oauth2Controller.logout);

module.exports = router;
