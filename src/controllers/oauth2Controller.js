const oauth2Service = require("../services/oauth2Service");
const jwtService = require("../utils/jwt");
const logger = require("../utils/logger");

class OAuth2Controller {
  // OAuth2 Authorization endpoint
  async authorize(req, res) {
    try {
      const params = req.query;

      // Validate authorization request
      const validation = await oauth2Service.validateAuthorizationRequest(
        params
      );
      const {
        client,
        scopes,
        state,
        nonce,
        codeChallenge,
        codeChallengeMethod,
      } = validation;

      // Check if user is authenticated
      if (!req.user) {
        // Store authorization request in session and redirect to login
        req.session = req.session || {};
        req.session.oauth2Request = {
          clientId: client.clientId,
          redirectUri: params.redirect_uri,
          responseType: params.response_type,
          scope: params.scope,
          state,
          nonce,
          codeChallenge,
          codeChallengeMethod,
        };

        return res.redirect("/login?redirect=/oauth2/authorize");
      }

      // User is authenticated, show consent screen or auto-approve
      const user = req.user;

      // Check if user has already consented to this client and scopes
      // For now, auto-approve. In production, you'd check consent records
      const isApproved = true;

      if (!isApproved) {
        // Show consent screen
        return res.render("consent", {
          client,
          scopes,
          user,
          state,
        });
      }

      // Generate authorization code
      const authorizationCode = await oauth2Service.generateAuthorizationCode(
        user,
        client,
        scopes,
        params.redirect_uri,
        nonce,
        codeChallenge,
        codeChallengeMethod
      );

      // Build redirect URI with authorization code
      const redirectUrl = new URL(params.redirect_uri);
      redirectUrl.searchParams.set("code", authorizationCode);
      if (state) {
        redirectUrl.searchParams.set("state", state);
      }

      logger.info("Authorization code generated", {
        userId: user._id,
        clientId: client.clientId,
        scopes,
      });

      res.redirect(redirectUrl.toString());
    } catch (error) {
      logger.error("Authorization failed:", error);

      const errorResponse = {
        error: error.message || "server_error",
        error_description: "Authorization failed",
      };

      if (req.query.redirect_uri) {
        const redirectUrl = new URL(req.query.redirect_uri);
        redirectUrl.searchParams.set("error", errorResponse.error);
        redirectUrl.searchParams.set(
          "error_description",
          errorResponse.error_description
        );
        if (req.query.state) {
          redirectUrl.searchParams.set("state", req.query.state);
        }
        return res.redirect(redirectUrl.toString());
      }

      res.status(400).json(errorResponse);
    }
  }

  // OAuth2 Token endpoint
  async token(req, res) {
    try {
      const {
        grant_type,
        client_id,
        client_secret,
        code,
        redirect_uri,
        refresh_token,
        username,
        password,
        scope,
        code_verifier,
      } = req.body;

      // Authenticate client
      const client = req.client;

      let tokenResponse;

      switch (grant_type) {
        case "authorization_code":
          tokenResponse = await oauth2Service.exchangeAuthorizationCode(
            code,
            client,
            redirect_uri,
            code_verifier
          );
          break;

        case "refresh_token":
          tokenResponse = await oauth2Service.refreshTokens(
            refresh_token,
            client,
            scope
          );
          break;

        case "client_credentials":
          tokenResponse = await oauth2Service.clientCredentials(client, scope);
          break;

        case "password":
          tokenResponse = await oauth2Service.passwordCredentials(
            client,
            username,
            password,
            scope
          );
          break;

        default:
          return res.status(400).json({
            error: "unsupported_grant_type",
            error_description: "Unsupported grant type",
          });
      }

      // Increment client usage
      await client.incrementUsage();

      logger.info("Token issued successfully", {
        clientId: client.clientId,
        grantType: grant_type,
      });

      res.json(tokenResponse);
    } catch (error) {
      logger.error("Token issuance failed:", error);

      const errorResponse = {
        error: error.message || "server_error",
        error_description: "Token issuance failed",
      };

      res.status(400).json(errorResponse);
    }
  }

  // OAuth2 UserInfo endpoint (OpenID Connect)
  async userinfo(req, res) {
    try {
      // Extract access token from Authorization header
      const authHeader = req.headers.authorization;
      if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({
          error: "invalid_token",
          error_description: "Access token required",
        });
      }

      const accessToken = authHeader.substring(7);

      // Get user info based on token scopes
      const userInfo = await oauth2Service.getUserInfo(accessToken);

      logger.info("UserInfo requested", {
        userId: userInfo.sub,
      });

      res.json(userInfo);
    } catch (error) {
      logger.error("UserInfo request failed:", error);

      res.status(401).json({
        error: "invalid_token",
        error_description: "Invalid access token",
      });
    }
  }

  // OAuth2 Token Revocation endpoint
  async revoke(req, res) {
    try {
      const { token, token_type_hint } = req.body;

      if (!token) {
        return res.status(400).json({
          error: "invalid_request",
          error_description: "Token is required",
        });
      }

      // Authenticate client
      const client = req.client;

      // Revoke token
      await oauth2Service.revokeToken(token, token_type_hint, client);

      logger.info("Token revoked successfully", {
        clientId: client.clientId,
        tokenTypeHint: token_type_hint,
      });

      res.status(200).end();
    } catch (error) {
      logger.error("Token revocation failed:", error);

      res.status(400).json({
        error: "invalid_request",
        error_description: "Token revocation failed",
      });
    }
  }

  // OAuth2 Introspection endpoint (RFC 7662)
  async introspect(req, res) {
    try {
      const { token, token_type_hint } = req.body;

      if (!token) {
        return res.status(400).json({
          error: "invalid_request",
          error_description: "Token is required",
        });
      }

      // Authenticate client
      const client = req.client;

      // Validate token
      const tokenInfo = await oauth2Service.validateAccessToken(token);

      if (!tokenInfo) {
        return res.json({
          active: false,
        });
      }

      // Check if client is authorized to introspect this token
      if (tokenInfo.clientId !== client.clientId) {
        return res.json({
          active: false,
        });
      }

      const response = {
        active: true,
        scope: tokenInfo.scopes.join(" "),
        client_id: tokenInfo.clientId,
        username: tokenInfo.user?.email,
        token_type: "Bearer",
        exp: Math.floor(Date.now() / 1000) + 900, // 15 minutes from now
        iat: Math.floor(Date.now() / 1000),
        nbf: Math.floor(Date.now() / 1000),
        sub: tokenInfo.userId,
        aud: tokenInfo.clientId,
        iss: process.env.HOST || "http://localhost:3000",
        jti: crypto.randomBytes(16).toString("hex"),
      };

      // Add user info if available
      if (tokenInfo.user) {
        response.user_id = tokenInfo.user.id;
        response.email = tokenInfo.user.email;
        response.role = tokenInfo.user.role;
      }

      logger.info("Token introspection requested", {
        clientId: client.clientId,
        tokenActive: true,
      });

      res.json(response);
    } catch (error) {
      logger.error("Token introspection failed:", error);

      res.status(400).json({
        error: "invalid_request",
        error_description: "Token introspection failed",
      });
    }
  }

  // OAuth2 Discovery endpoint (OpenID Connect)
  async discovery(req, res) {
    const baseUrl = process.env.HOST || "http://localhost:3000";

    const discovery = {
      issuer: baseUrl,
      authorization_endpoint: `${baseUrl}/oauth2/authorize`,
      token_endpoint: `${baseUrl}/oauth2/token`,
      userinfo_endpoint: `${baseUrl}/oauth2/userinfo`,
      revocation_endpoint: `${baseUrl}/oauth2/revoke`,
      introspection_endpoint: `${baseUrl}/oauth2/introspect`,
      jwks_uri: `${baseUrl}/oauth2/jwks`,

      // Supported scopes
      scopes_supported: oauth2Service.getSupportedScopes(),

      // Supported response types
      response_types_supported: oauth2Service.getSupportedResponseTypes(),

      // Supported grant types
      grant_types_supported: oauth2Service.getSupportedGrantTypes(),

      // Supported token endpoint authentication methods
      token_endpoint_auth_methods_supported: [
        "client_secret_basic",
        "client_secret_post",
        "none",
      ],

      // Supported subject identifier types
      subject_types_supported: ["public"],

      // Supported ID token signing algorithms
      id_token_signing_alg_values_supported: ["HS256"],

      // Supported claims
      claims_supported: [
        "sub",
        "iss",
        "name",
        "given_name",
        "family_name",
        "preferred_username",
        "email",
        "email_verified",
        "picture",
        "locale",
        "updated_at",
        "role",
        "account_type",
      ],

      // Code challenge methods
      code_challenge_methods_supported: ["S256", "plain"],
    };

    res.json(discovery);
  }

  // JWKS endpoint (JSON Web Key Set)
  async jwks(req, res) {
    // For now, return empty JWKS since we're using symmetric keys
    // In production, you'd use asymmetric keys and return the public keys
    const jwks = {
      keys: [],
    };

    res.json(jwks);
  }

  // Consent screen handler
  async consent(req, res) {
    try {
      const { approve, client_id, scope, state } = req.body;

      if (!req.user) {
        return res.status(401).json({
          error: "access_denied",
          error_description: "User not authenticated",
        });
      }

      if (!approve) {
        // User denied consent
        const redirectUrl = new URL(req.session.oauth2Request.redirect_uri);
        redirectUrl.searchParams.set("error", "access_denied");
        redirectUrl.searchParams.set(
          "error_description",
          "User denied consent"
        );
        if (state) {
          redirectUrl.searchParams.set("state", state);
        }

        delete req.session.oauth2Request;
        return res.redirect(redirectUrl.toString());
      }

      // User approved consent, continue with authorization
      const oauth2Request = req.session.oauth2Request;
      delete req.session.oauth2Request;

      // Reconstruct the authorization request
      req.query = {
        ...oauth2Request,
        client_id,
        scope,
        state,
      };

      // Call authorize again
      return this.authorize(req, res);
    } catch (error) {
      logger.error("Consent handling failed:", error);

      res.status(400).json({
        error: "consent_failed",
        error_description: "Failed to process consent",
      });
    }
  }

  // Logout endpoint (OpenID Connect)
  async logout(req, res) {
    try {
      const { id_token_hint, post_logout_redirect_uri, state } = req.query;

      // Validate ID token hint if provided
      if (id_token_hint) {
        try {
          const decoded = jwtService.verifyIdToken(id_token_hint);
          // You might want to validate the token further
        } catch (error) {
          logger.warn("Invalid ID token hint provided for logout");
        }
      }

      // Clear session
      if (req.session) {
        req.session.destroy();
      }

      // Redirect to post-logout URI if provided
      if (post_logout_redirect_uri) {
        const redirectUrl = new URL(post_logout_redirect_uri);
        if (state) {
          redirectUrl.searchParams.set("state", state);
        }
        return res.redirect(redirectUrl.toString());
      }

      res.json({
        message: "Logged out successfully",
      });
    } catch (error) {
      logger.error("Logout failed:", error);

      res.status(400).json({
        error: "logout_failed",
        error_description: "Failed to logout",
      });
    }
  }
}

module.exports = new OAuth2Controller();
