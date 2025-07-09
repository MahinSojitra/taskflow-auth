const crypto = require("crypto");
const jwtService = require("../utils/jwt");
const pkceService = require("../utils/pkce");
const User = require("../models/User");
const Client = require("../models/Client");
const Token = require("../models/Token");
const logger = require("../utils/logger");

class OAuth2Service {
  constructor() {
    this.supportedScopes = [
      "openid",
      "profile",
      "email",
      "read",
      "write",
      "admin",
    ];
    this.supportedGrantTypes = [
      "authorization_code",
      "refresh_token",
      "client_credentials",
      "password",
    ];
    this.supportedResponseTypes = ["code", "token", "id_token"];
  }

  // Validate OAuth2 authorization request
  async validateAuthorizationRequest(params) {
    const {
      response_type,
      client_id,
      redirect_uri,
      scope,
      state,
      nonce,
      code_challenge,
      code_challenge_method,
    } = params;

    // Validate client
    const client = await Client.findByClientId(client_id);
    if (!client) {
      throw new Error("invalid_client");
    }

    // Validate redirect URI
    if (!client.isValidRedirectUri(redirect_uri)) {
      throw new Error("invalid_redirect_uri");
    }

    // Validate response type
    if (!client.supportsResponseType(response_type)) {
      throw new Error("unsupported_response_type");
    }

    // Validate scopes
    const requestedScopes = scope
      ? scope.split(" ")
      : ["openid", "profile", "email"];
    const validScopes = requestedScopes.filter((s) => client.hasScope(s));
    if (validScopes.length === 0) {
      throw new Error("invalid_scope");
    }

    // Validate PKCE for public clients
    if (client.requiresPKCE()) {
      if (!code_challenge) {
        throw new Error("code_challenge_required");
      }
      if (
        !client.supportsCodeChallengeMethod(code_challenge_method || "S256")
      ) {
        throw new Error("unsupported_code_challenge_method");
      }
    }

    return {
      client,
      scopes: validScopes,
      state,
      nonce,
      codeChallenge: code_challenge,
      codeChallengeMethod: code_challenge_method || "S256",
    };
  }

  // Generate authorization code
  async generateAuthorizationCode(
    user,
    client,
    scopes,
    redirectUri,
    nonce = null,
    codeChallenge = null,
    codeChallengeMethod = null
  ) {
    const authorizationCode = crypto.randomBytes(32).toString("hex");

    const tokenDoc = new Token({
      tokenType: "authorization_code",
      token: authorizationCode,
      clientId: client.clientId,
      userId: user._id,
      scopes: scopes,
      redirectUri: redirectUri,
      codeVerifier: null, // Will be set when code is exchanged
      codeChallenge: codeChallenge,
      codeChallengeMethod: codeChallengeMethod,
      ipAddress: req?.ip,
      userAgent: req?.get("User-Agent"),
    });

    await tokenDoc.save();

    // Store nonce for ID token if needed
    if (nonce && scopes.includes("openid")) {
      tokenDoc.jwtPayload = new Map([["nonce", nonce]]);
      await tokenDoc.save();
    }

    return authorizationCode;
  }

  // Exchange authorization code for tokens
  async exchangeAuthorizationCode(
    code,
    client,
    redirectUri,
    codeVerifier = null
  ) {
    // Find and validate authorization code
    const authCodeDoc = await Token.findByAuthorizationCode(code);
    if (!authCodeDoc) {
      throw new Error("invalid_grant");
    }

    // Verify client
    if (authCodeDoc.clientId !== client.clientId) {
      throw new Error("invalid_client");
    }

    // Verify redirect URI
    if (authCodeDoc.redirectUri !== redirectUri) {
      throw new Error("invalid_grant");
    }

    // Verify PKCE if required
    if (authCodeDoc.codeChallenge) {
      if (!codeVerifier) {
        throw new Error("code_verifier_required");
      }

      if (
        !pkceService.verifyCodeVerifier(
          codeVerifier,
          authCodeDoc.codeChallenge,
          authCodeDoc.codeChallengeMethod
        )
      ) {
        throw new Error("invalid_code_verifier");
      }
    }

    // Get user
    const user = await User.findById(authCodeDoc.userId);
    if (!user || !user.isActive) {
      throw new Error("invalid_grant");
    }

    // Revoke authorization code
    await authCodeDoc.revoke(user._id, "Code exchanged for tokens");

    // Generate tokens
    const includeIdToken = authCodeDoc.scopes.includes("openid");
    const nonce = authCodeDoc.jwtPayload?.get("nonce");

    const tokenResponse = jwtService.generateOAuth2Response(
      user,
      client.clientId,
      authCodeDoc.scopes,
      includeIdToken,
      nonce
    );

    // Store tokens in database
    await this.storeTokens(
      tokenResponse,
      user._id,
      client.clientId,
      authCodeDoc.scopes,
      code
    );

    return tokenResponse;
  }

  // Exchange refresh token for new tokens
  async refreshTokens(refreshToken, client, requestedScopes = null) {
    // Verify refresh token
    const decoded = jwtService.verifyRefreshToken(refreshToken);

    // Find token in database
    const tokenDoc = await Token.findValidToken(refreshToken, "refresh_token");
    if (!tokenDoc) {
      throw new Error("invalid_grant");
    }

    // Verify client
    if (tokenDoc.clientId !== client.clientId) {
      throw new Error("invalid_client");
    }

    // Get user
    const user = await User.findById(decoded.sub);
    if (!user || !user.isActive) {
      throw new Error("invalid_grant");
    }

    // Validate requested scopes
    const scopes = requestedScopes
      ? requestedScopes.split(" ").filter((s) => tokenDoc.scopes.includes(s))
      : tokenDoc.scopes;

    if (scopes.length === 0) {
      throw new Error("invalid_scope");
    }

    // Revoke old refresh token
    await tokenDoc.revoke(user._id, "Token refreshed");

    // Generate new tokens
    const tokenResponse = jwtService.generateTokenPair(
      user,
      client.clientId,
      scopes
    );

    // Store new tokens
    await this.storeTokens(tokenResponse, user._id, client.clientId, scopes);

    return tokenResponse;
  }

  // Client credentials flow
  async clientCredentials(client, requestedScopes = null) {
    const scopes = requestedScopes
      ? requestedScopes.split(" ").filter((s) => client.hasScope(s))
      : client.scopes;

    if (scopes.length === 0) {
      throw new Error("invalid_scope");
    }

    // For client credentials, we create a system user or use client as subject
    const tokenResponse = {
      access_token: jwtService.generateAccessToken(
        {
          _id: client._id,
          email: client.name,
          role: "client",
        },
        client.clientId,
        scopes
      ),
      token_type: "Bearer",
      expires_in: parseInt(process.env.JWT_ACCESS_EXPIRES_IN || "900"),
      scope: scopes.join(" "),
    };

    // Store access token
    await this.storeAccessToken(
      tokenResponse.access_token,
      null,
      client.clientId,
      scopes
    );

    return tokenResponse;
  }

  // Resource owner password credentials flow
  async passwordCredentials(
    client,
    username,
    password,
    requestedScopes = null
  ) {
    // Find user
    const user = await User.findByEmailOrUsername(username);
    if (!user || !user.isActive) {
      throw new Error("invalid_grant");
    }

    // Verify password
    const isValidPassword = await user.comparePassword(password);
    if (!isValidPassword) {
      await user.incLoginAttempts();
      throw new Error("invalid_grant");
    }

    // Reset login attempts on successful login
    await user.resetLoginAttempts();
    user.lastLogin = new Date();
    await user.save();

    // Validate scopes
    const scopes = requestedScopes
      ? requestedScopes.split(" ").filter((s) => client.hasScope(s))
      : client.scopes;

    if (scopes.length === 0) {
      throw new Error("invalid_scope");
    }

    // Generate tokens
    const tokenResponse = jwtService.generateTokenPair(
      user,
      client.clientId,
      scopes
    );

    // Store tokens
    await this.storeTokens(tokenResponse, user._id, client.clientId, scopes);

    return tokenResponse;
  }

  // Store tokens in database
  async storeTokens(
    tokenResponse,
    userId,
    clientId,
    scopes,
    authorizationCode = null
  ) {
    const tokens = [];

    // Store access token
    if (tokenResponse.access_token) {
      const accessToken = new Token({
        tokenType: "access_token",
        token: tokenResponse.access_token,
        clientId: clientId,
        userId: userId,
        scopes: scopes,
        authorizationCode: authorizationCode,
        ipAddress: req?.ip,
        userAgent: req?.get("User-Agent"),
      });
      tokens.push(accessToken);
    }

    // Store refresh token
    if (tokenResponse.refresh_token) {
      const refreshToken = new Token({
        tokenType: "refresh_token",
        token: tokenResponse.refresh_token,
        clientId: clientId,
        userId: userId,
        scopes: scopes,
        authorizationCode: authorizationCode,
        ipAddress: req?.ip,
        userAgent: req?.get("User-Agent"),
      });
      tokens.push(refreshToken);
    }

    // Store ID token
    if (tokenResponse.id_token) {
      const idToken = new Token({
        tokenType: "id_token",
        token: tokenResponse.id_token,
        clientId: clientId,
        userId: userId,
        scopes: scopes,
        authorizationCode: authorizationCode,
        jwtPayload: new Map([
          ["payload", jwtService.decodeToken(tokenResponse.id_token)],
        ]),
      });
      tokens.push(idToken);
    }

    await Promise.all(tokens.map((token) => token.save()));
  }

  // Store access token only
  async storeAccessToken(accessToken, userId, clientId, scopes) {
    const token = new Token({
      tokenType: "access_token",
      token: accessToken,
      clientId: clientId,
      userId: userId,
      scopes: scopes,
      ipAddress: req?.ip,
      userAgent: req?.get("User-Agent"),
    });

    await token.save();
  }

  // Get user info for OAuth2 userinfo endpoint
  async getUserInfo(accessToken) {
    const decoded = jwtService.verifyAccessToken(accessToken);
    const user = await User.findById(decoded.sub).select("-password");

    if (!user || !user.isActive) {
      throw new Error("invalid_token");
    }

    const scopes = decoded.scopes || [];
    const userInfo = {
      sub: user._id.toString(),
    };

    // Add claims based on scopes
    if (scopes.includes("profile")) {
      Object.assign(userInfo, {
        name: user.fullName,
        given_name: user.firstName,
        family_name: user.lastName,
        preferred_username: user.username,
        picture: user.profile?.avatar,
        locale: user.preferences?.language || "en",
        updated_at: Math.floor(user.updatedAt.getTime() / 1000),
      });
    }

    if (scopes.includes("email")) {
      Object.assign(userInfo, {
        email: user.email,
        email_verified: user.isEmailVerified,
      });
    }

    // Add custom claims
    Object.assign(userInfo, {
      role: user.role,
      account_type: user.accountType,
    });

    return userInfo;
  }

  // Revoke token
  async revokeToken(token, tokenTypeHint = null, client) {
    let tokenDoc = null;

    // Try to find token by type hint
    if (tokenTypeHint) {
      tokenDoc = await Token.findValidToken(token, tokenTypeHint);
    }

    // If not found, try all token types
    if (!tokenDoc) {
      for (const type of ["access_token", "refresh_token"]) {
        tokenDoc = await Token.findValidToken(token, type);
        if (tokenDoc) break;
      }
    }

    if (!tokenDoc) {
      // Token not found, but we return success as per RFC 7009
      return true;
    }

    // Verify client owns the token
    if (tokenDoc.clientId !== client.clientId) {
      throw new Error("invalid_client");
    }

    // Revoke the token
    await tokenDoc.revoke(null, "Token revoked by client");

    return true;
  }

  // Validate access token
  async validateAccessToken(accessToken) {
    try {
      const decoded = jwtService.verifyAccessToken(accessToken);
      const tokenDoc = await Token.findValidToken(accessToken, "access_token");

      if (!tokenDoc) {
        return null;
      }

      return {
        valid: true,
        clientId: decoded.aud,
        userId: decoded.sub,
        scopes: decoded.scopes || [],
        user: decoded.user,
      };
    } catch (error) {
      return null;
    }
  }

  // Get supported scopes
  getSupportedScopes() {
    return this.supportedScopes;
  }

  // Get supported grant types
  getSupportedGrantTypes() {
    return this.supportedGrantTypes;
  }

  // Get supported response types
  getSupportedResponseTypes() {
    return this.supportedResponseTypes;
  }
}

module.exports = new OAuth2Service();
