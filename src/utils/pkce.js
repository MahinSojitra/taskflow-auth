const crypto = require("crypto");

class PKCEService {
  constructor() {
    this.codeVerifierLength =
      parseInt(process.env.PKCE_CODE_VERIFIER_LENGTH) || 128;
    this.defaultMethod = process.env.PKCE_CODE_CHALLENGE_METHOD || "S256";
  }

  // Generate a random code verifier
  generateCodeVerifier(length = this.codeVerifierLength) {
    const validChars =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
    let codeVerifier = "";

    for (let i = 0; i < length; i++) {
      codeVerifier += validChars.charAt(
        Math.floor(Math.random() * validChars.length)
      );
    }

    return codeVerifier;
  }

  // Generate code challenge from code verifier
  generateCodeChallenge(codeVerifier, method = this.defaultMethod) {
    if (method === "S256") {
      // SHA256 hash of code verifier, base64url encoded
      const hash = crypto.createHash("sha256").update(codeVerifier).digest();
      return this.base64URLEncode(hash);
    } else if (method === "plain") {
      // Plain method - code challenge equals code verifier
      return codeVerifier;
    } else {
      throw new Error(`Unsupported PKCE method: ${method}`);
    }
  }

  // Generate both code verifier and challenge
  generateCodePair(method = this.defaultMethod) {
    const codeVerifier = this.generateCodeVerifier();
    const codeChallenge = this.generateCodeChallenge(codeVerifier, method);

    return {
      codeVerifier,
      codeChallenge,
      method,
    };
  }

  // Verify code verifier against code challenge
  verifyCodeVerifier(codeVerifier, codeChallenge, method = this.defaultMethod) {
    const expectedChallenge = this.generateCodeChallenge(codeVerifier, method);
    return expectedChallenge === codeChallenge;
  }

  // Base64URL encoding (RFC 4648)
  base64URLEncode(buffer) {
    return buffer
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=/g, "");
  }

  // Base64URL decoding
  base64URLDecode(str) {
    // Add padding back
    str += "=".repeat((4 - (str.length % 4)) % 4);
    // Replace URL-safe characters
    str = str.replace(/-/g, "+").replace(/_/g, "/");
    return Buffer.from(str, "base64");
  }

  // Validate code verifier format
  validateCodeVerifier(codeVerifier) {
    if (!codeVerifier || typeof codeVerifier !== "string") {
      return false;
    }

    // Must be between 43 and 128 characters
    if (codeVerifier.length < 43 || codeVerifier.length > 128) {
      return false;
    }

    // Must only contain allowed characters
    const validCharsRegex = /^[A-Za-z0-9\-._~]+$/;
    return validCharsRegex.test(codeVerifier);
  }

  // Validate code challenge format
  validateCodeChallenge(codeChallenge) {
    if (!codeChallenge || typeof codeChallenge !== "string") {
      return false;
    }

    // Must be between 43 and 128 characters
    if (codeChallenge.length < 43 || codeChallenge.length > 128) {
      return false;
    }

    // Must only contain allowed characters
    const validCharsRegex = /^[A-Za-z0-9\-._~]+$/;
    return validCharsRegex.test(codeChallenge);
  }

  // Validate PKCE method
  validateMethod(method) {
    return ["S256", "plain"].includes(method);
  }

  // Get supported PKCE methods
  getSupportedMethods() {
    return ["S256", "plain"];
  }

  // Create PKCE parameters for OAuth2 authorization request
  createPKCEParams(method = this.defaultMethod) {
    const { codeVerifier, codeChallenge } = this.generateCodePair(method);

    return {
      code_verifier: codeVerifier,
      code_challenge: codeChallenge,
      code_challenge_method: method,
    };
  }

  // Extract PKCE parameters from request
  extractPKCEParams(req) {
    const { code_challenge, code_challenge_method } = req.query;

    if (!code_challenge) {
      return null;
    }

    const method = code_challenge_method || this.defaultMethod;

    if (!this.validateMethod(method)) {
      throw new Error(`Unsupported PKCE method: ${method}`);
    }

    if (!this.validateCodeChallenge(code_challenge)) {
      throw new Error("Invalid code challenge format");
    }

    return {
      code_challenge: code_challenge,
      code_challenge_method: method,
    };
  }

  // Validate PKCE parameters in token request
  validatePKCEInTokenRequest(req, storedCodeVerifier) {
    const { code_verifier } = req.body;

    if (!code_verifier) {
      throw new Error("code_verifier is required for PKCE");
    }

    if (!this.validateCodeVerifier(code_verifier)) {
      throw new Error("Invalid code verifier format");
    }

    // Verify against stored code verifier
    if (code_verifier !== storedCodeVerifier) {
      throw new Error("Invalid code verifier");
    }

    return true;
  }
}

module.exports = new PKCEService();
