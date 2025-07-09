const express = require("express");
const router = express.Router();
const clientController = require("../controllers/clientController");
const { verifyToken, requireRole } = require("../middleware/auth");
const {
  validateClientRegistration,
  validatePagination,
  validateId,
  validateSearch,
} = require("../middleware/validation");

/**
 * @swagger
 * /clients:
 *   post:
 *     summary: Register new OAuth2 client
 *     tags: [Clients]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - name
 *               - clientType
 *               - redirectUris
 *             properties:
 *               name:
 *                 type: string
 *                 maxLength: 100
 *               description:
 *                 type: string
 *                 maxLength: 500
 *               clientType:
 *                 type: string
 *                 enum: [public, confidential]
 *               redirectUris:
 *                 type: array
 *                 items:
 *                   type: string
 *                   format: uri
 *               scopes:
 *                 type: array
 *                 items:
 *                   type: string
 *                   enum: [openid, profile, email, read, write, admin]
 *               grantTypes:
 *                 type: array
 *                 items:
 *                   type: string
 *                   enum: [authorization_code, client_credentials, refresh_token, password]
 *               responseTypes:
 *                 type: array
 *                 items:
 *                   type: string
 *                   enum: [code, token, id_token]
 *               requirePKCE:
 *                 type: boolean
 *               codeChallengeMethods:
 *                 type: array
 *                 items:
 *                   type: string
 *                   enum: [S256, plain]
 *               allowedOrigins:
 *                 type: array
 *                 items:
 *                   type: string
 *                   format: uri
 *               website:
 *                 type: string
 *                 format: uri
 *               privacyPolicy:
 *                 type: string
 *                 format: uri
 *               termsOfService:
 *                 type: string
 *                 format: uri
 *     responses:
 *       201:
 *         description: Client registered successfully
 *       400:
 *         description: Validation error
 *       401:
 *         description: Unauthorized
 */
router.post(
  "/",
  verifyToken,
  validateClientRegistration,
  clientController.registerClient
);

/**
 * @swagger
 * /clients:
 *   get:
 *     summary: Get user's OAuth2 clients
 *     tags: [Clients]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: page
 *         schema:
 *           type: integer
 *           minimum: 1
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           minimum: 1
 *           maximum: 100
 *       - in: query
 *         name: sort
 *         schema:
 *           type: string
 *       - in: query
 *         name: order
 *         schema:
 *           type: string
 *           enum: [asc, desc]
 *     responses:
 *       200:
 *         description: Clients retrieved successfully
 *       401:
 *         description: Unauthorized
 */
router.get("/", verifyToken, validatePagination, clientController.getMyClients);

/**
 * @swagger
 * /clients/search:
 *   get:
 *     summary: Search user's OAuth2 clients
 *     tags: [Clients]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: q
 *         schema:
 *           type: string
 *           minLength: 1
 *           maxLength: 100
 *       - in: query
 *         name: type
 *         schema:
 *           type: string
 *           enum: [public, confidential]
 *       - in: query
 *         name: page
 *         schema:
 *           type: integer
 *           minimum: 1
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           minimum: 1
 *           maximum: 100
 *     responses:
 *       200:
 *         description: Search results
 *       400:
 *         description: Validation error
 *       401:
 *         description: Unauthorized
 */
router.get(
  "/search",
  verifyToken,
  validateSearch,
  clientController.searchClients
);

/**
 * @swagger
 * /clients/{id}:
 *   get:
 *     summary: Get specific OAuth2 client
 *     tags: [Clients]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *           format: objectId
 *     responses:
 *       200:
 *         description: Client retrieved successfully
 *       401:
 *         description: Unauthorized
 *       404:
 *         description: Client not found
 */
router.get("/:id", verifyToken, validateId, clientController.getClient);

/**
 * @swagger
 * /clients/{id}:
 *   put:
 *     summary: Update OAuth2 client
 *     tags: [Clients]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *           format: objectId
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *                 maxLength: 100
 *               description:
 *                 type: string
 *                 maxLength: 500
 *               redirectUris:
 *                 type: array
 *                 items:
 *                   type: string
 *                   format: uri
 *               scopes:
 *                 type: array
 *                 items:
 *                   type: string
 *                   enum: [openid, profile, email, read, write, admin]
 *               grantTypes:
 *                 type: array
 *                 items:
 *                   type: string
 *                   enum: [authorization_code, client_credentials, refresh_token, password]
 *               responseTypes:
 *                 type: array
 *                 items:
 *                   type: string
 *                   enum: [code, token, id_token]
 *               requirePKCE:
 *                 type: boolean
 *               codeChallengeMethods:
 *                 type: array
 *                 items:
 *                   type: string
 *                   enum: [S256, plain]
 *               allowedOrigins:
 *                 type: array
 *                 items:
 *                   type: string
 *                   format: uri
 *               website:
 *                 type: string
 *                 format: uri
 *               privacyPolicy:
 *                 type: string
 *                 format: uri
 *               termsOfService:
 *                 type: string
 *                 format: uri
 *     responses:
 *       200:
 *         description: Client updated successfully
 *       400:
 *         description: Validation error
 *       401:
 *         description: Unauthorized
 *       404:
 *         description: Client not found
 */
router.put("/:id", verifyToken, validateId, clientController.updateClient);

/**
 * @swagger
 * /clients/{id}/regenerate-secret:
 *   post:
 *     summary: Regenerate client secret
 *     tags: [Clients]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *           format: objectId
 *     responses:
 *       200:
 *         description: Client secret regenerated successfully
 *       401:
 *         description: Unauthorized
 *       404:
 *         description: Client not found
 */
router.post(
  "/:id/regenerate-secret",
  verifyToken,
  validateId,
  clientController.regenerateClientSecret
);

/**
 * @swagger
 * /clients/{id}:
 *   delete:
 *     summary: Delete OAuth2 client
 *     tags: [Clients]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *           format: objectId
 *     responses:
 *       200:
 *         description: Client deleted successfully
 *       401:
 *         description: Unauthorized
 *       404:
 *         description: Client not found
 */
router.delete("/:id", verifyToken, validateId, clientController.deleteClient);

/**
 * @swagger
 * /clients/{id}/stats:
 *   get:
 *     summary: Get client statistics
 *     tags: [Clients]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *           format: objectId
 *     responses:
 *       200:
 *         description: Client statistics retrieved successfully
 *       401:
 *         description: Unauthorized
 *       404:
 *         description: Client not found
 */
router.get(
  "/:id/stats",
  verifyToken,
  validateId,
  clientController.getClientStats
);

/**
 * @swagger
 * /clients/{id}/analytics:
 *   get:
 *     summary: Get client usage analytics
 *     tags: [Clients]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *           format: objectId
 *       - in: query
 *         name: period
 *         schema:
 *           type: string
 *           enum: [7d, 30d, 90d]
 *           default: 30d
 *     responses:
 *       200:
 *         description: Client analytics retrieved successfully
 *       401:
 *         description: Unauthorized
 *       404:
 *         description: Client not found
 */
router.get(
  "/:id/analytics",
  verifyToken,
  validateId,
  clientController.getClientAnalytics
);

module.exports = router;
