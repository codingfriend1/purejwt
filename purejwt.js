const crypto = require("crypto");

// The PureJWT class generates, signs and verifies JSON Web Tokens
class PureJWT {
  // Private variables for secret, private and public keys

  constructor({
    algorithm,
    privateKey,
    publicKey,
    secret,
    allowedIssuers = "",
    allowedAudiences = "",
    durationInMinutes = 24 * 60,
  }) {
    // Initialize variables
    this.secret = secret;
    this.privateKey = privateKey;
    this.publicKey = publicKey;
    this.allowedIssuers = allowedIssuers;
    this.allowedAudiences = allowedAudiences;
    this.durationInMinutes = durationInMinutes;
    this.algorithm =
      algorithm ||
      (this.secret !== undefined && "HS256") ||
      PureJWT.inferAlgorithmFromKey(this.privateKey);
    this.sigAlg = PureJWT.SUPPORTED_ALGORITHMS[this.algorithm];

    // Verify the given algorithm and keys
    this.verifyAlgorithmAndKeys();
  }

  // Define an array of valid algorithms
  static SUPPORTED_ALGORITHMS = {
    HS256: "sha256",
    HS384: "sha384",
    HS512: "sha512",
    RS256: "RSA-SHA256",
    RS384: "RSA-SHA384",
    RS512: "RSA-SHA512",
    ES256: "sha256",
    ES384: "sha384",
    ES512: "sha512",
    PS256: "RSA-SHA256",
    PS384: "RSA-SHA384",
    PS512: "RSA-SHA512",
  };

  // Generate a secret key using crypto
  static generateSecret() {
    return crypto.randomBytes(32).toString("hex");
  }

  /**
   * Generate public and private keys using crypto
   * @param {string} algorithm - The algorithm to use (rsa | ec | rsa-pss)
   * @param {Object} options - The options for the key generation
   * @param {number} options.modulusLength - The length of the modulus
   * @param {string} options.namedCurve - The name of the curve to use
   * @return {Object} The private and public keys
   */
  static generatePublicPrivateKeys(algorithm = "rsa", options = {}, singleLine = false) {
    try {
      if (algorithm === "rsa")
        options.modulusLength = options.modulusLength || 2048;
      if (algorithm === "ec")
        options.namedCurve = options.namedCurve || "prime256v1";

      options.privateKeyEncoding = options.privateKeyEncoding || { type: "pkcs8", format: "pem" }
      options.publicKeyEncoding = options.publicKeyEncoding || { type: "spki", format: "pem" }

      let { privateKey, publicKey } = crypto.generateKeyPairSync(
        algorithm,
        options
      );

      if(singleLine) {
        return {
          privateKey: privateKey.replace(/\n/g, "\\n"),
          publicKey: publicKey.replace(/\n/g, "\\n")
        }
      }
      

      return {
        privateKey,
        publicKey
      };
    } catch (err) {
      throw new PureJWT.PureJWTError(err.message, 500, err);
    }
  }

  /**
   * Generates a JWT
   * @param {Object} payload - JWT payload
   * @return {string} Generated JWT
   */
  createToken(payload = {}) {
    if (
      typeof payload !== "object" ||
      payload === null ||
      Array.isArray(payload) ||
      Object.keys(payload).length === 0
    ) {
      throw new PureJWT.PureJWTError(
        "Payload must be an object with at least one key.",
        500
      );
    }

    payload = PureJWT.preverifyClaims({ ...payload });

    const header = { typ: "JWT", alg: this.algorithm };

    const content = PureJWT.encodeContent(header, payload);

    const signature = this.sign(content, true);

    return `${content}.${signature}`;
  }

  /**
   * Verifies a JWT
   * @param {string} token - JWT to verify
   * @return {Object} Decoded JWT
   */
  verifyToken(token) {
    if (!token) throw new PureJWT.PureJWTError("Token is missing", 400);

    const [headerB64, payloadB64, signatureB64] = token.split(".");

    const { header, payload } = PureJWT.decodeContent(headerB64, payloadB64);

    const isVerified = this.verifySignature(
      `${headerB64}.${payloadB64}`,
      signatureB64,
      header.alg || this.algorithm
    );

    if (!isVerified) {
      throw new PureJWT.PureJWTError("Token signature is invalid", 401);
    }

    this.verifyClaims(payload);

    return payload;
  }

  // Check if the provided algorithm and keys are valid
  verifyAlgorithmAndKeys() {
    if (!this.sigAlg) {
      throw new PureJWT.PureJWTError(
        `Invalid algorithm: ${this.algorithm}. Must be one of: ${Object.keys(
          PureJWT.SUPPORTED_ALGORITHMS
        ).join(", ")}`,
        500
      );
    }

    if (this.algorithm.includes("HS") && !this.secret) {
      throw new PureJWT.PureJWTError(
        "A synchronous algorithm must provide a secret.",
        500
      );
    }
    if (this.secret && typeof this.secret !== "string") {
      throw new PureJWT.PureJWTError("The secret must be a string", 500);
    }

    if (
      !this.algorithm.includes("HS") &&
      (!this.publicKey || !this.privateKey)
    ) {
      throw new PureJWT.PureJWTError(
        `An asynchronous algorithm must provide a 'publicKey' and 'privateKey'.`,
        500
      );
    }

    if (!PureJWT.isStringOrArrayOfStrings(this.allowedAudiences)) {
      throw new PureJWT.PureJWTError(
        `'audience' must be a String or an array of Strings.`,
        500
      );
    }

    if (!PureJWT.isStringOrArrayOfStrings(this.allowedIssuers)) {
      throw new PureJWT.PureJWTError(
        `'issuer' must be a String or an array of Strings.`,
        500
      );
    }
  }

  /**
   * Infers the algorithm from the provided key
   * @param {string} pemKey - Key from which to infer the algorithm
   * @return {string} Inferred algorithm
   */
  static inferAlgorithmFromKey(pemKey) {
    try {
      const keyObject = crypto.createPublicKey(pemKey);

      if (keyObject.asymmetricKeyType === "rsa") {
        const keyDetails = keyObject.export({ format: "jwk" });

        const modulusSize = Buffer.from(keyDetails.n, "base64").length;

        return `RS${modulusSize}`; // RS256, RS384, or RS512 based on modulus size
      } else if (keyObject.asymmetricKeyType === "ec") {
        const keyDetails = keyObject.export({ format: "jwk" });

        const curve = keyDetails.crv; // "P-256", "P-384", or "P-521"

        return curve === "P-256"
          ? "ES256"
          : curve === "P-384"
          ? "ES384"
          : "ES512";
      }

      throw new PureJWT.PureJWTError(
        `Cannot infer algorithm from privateKey.`,
        500,
        err
      );
    } catch (err) {
      throw new PureJWT.PureJWTError(
        `Cannot infer algorithm from privateKey.`,
        500,
        err
      );
    }
  }

  /**
   * Encodes the JWT header and payload
   * @param {Object} header - JWT header
   * @param {Object} payload - JWT payload
   * @return {string} Encoded header and payload
   */
  static encodeContent(header, payload) {

    const encodedHeader = Buffer.from(JSON.stringify(header)).toString(
      "base64url"
    );

    const encodedPayload = Buffer.from(JSON.stringify(payload)).toString(
      "base64url"
    );

    return `${encodedHeader}.${encodedPayload}`;
  }

  /**
   * Decodes the JWT header and payload
   * @param {string} headerB64 - Encoded header
   * @param {string} payloadB64 - Encoded payload
   * @return {Object} Decoded header and payload
   */
  static decodeContent(headerB64, payloadB64) {
    try {
      const header = JSON.parse(
        Buffer.from(headerB64, "base64url").toString("utf8")
      );
      const payload = JSON.parse(
        Buffer.from(payloadB64, "base64url").toString("utf8")
      );

      return { header, payload };
    } catch (err) {
      throw new PureJWT.PureJWTError("Token cannot be parsed.", 400, err);
    }
  }

  /**
   * Generates a JWT signature
   * @param {string} content - Encoded header and payload of JWT
   * @param {boolean} isSigning - Determines whether to pass `base64` to HMAC digest
   * @return {string} Generated signature
   */
  sign(content, isSigning) {
    if (this.algorithm.includes("HS")) {
      return crypto
        .createHmac(this.sigAlg, this.secret)
        .update(content)
        .digest(isSigning ? "base64url" : "");
    } else {
      let key;

      if (this.algorithm.includes("RS")) {
        key = this.privateKey;
      } else if (this.algorithm.includes("PS")) {
        key = {
          key: this.privateKey,
          padding: crypto.constants.RSA_PKCS1_PSS_PADDING, // Padding for PS algorithms
          saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST, // Salt length for PS algorithms
        };
      } else {
        key = { key: this.privateKey, dsaEncoding: "ieee-p1363" }; // Key for ES algorithms
      }

      return crypto
        .sign(this.sigAlg, Buffer.from(content), key)
        .toString("base64url");
    }
  }

  /**
   * Verifies a JWT signature
   * @param {string} contentB64 - Encoded header and payload of JWT as Base64, joined by a dot `${headerB64}.${payloadB64}`
   * @param {string} signatureB64 - Encoded signature as Base64
   * @return {boolean} Content matches signature
   */
  verifySignature(contentB64, signatureB64, alg) {
    const signature = Buffer.from(signatureB64, "base64url");

    if (alg.includes("HS")) {
      return crypto.timingSafeEqual(this.sign(contentB64), signature);
    } else {
      let key;
      let padding;

      if (alg.includes("RS")) {
        key = this.publicKey;
      } else if (alg.includes("PS")) {
        key = {
          key: this.publicKey,
          padding: crypto.constants.RSA_PKCS1_PSS_PADDING, // Padding for PS algorithms
          saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
        };
      } else {
        key = { key: this.publicKey, dsaEncoding: "ieee-p1363" }; // Key for ES algorithms
      }

      return crypto.verify(
        this.sigAlg,
        Buffer.from(contentB64),
        key,
        signature
      );
    }
  }

  // Verifies token's claims
  verifyClaims(payload) {
    payload = PureJWT.preverifyClaims(payload);

    const nowInSeconds = PureJWT.getSeconds();

    const tokenDuration = this.durationInMinutes * 60;

    const expiration = payload.exp || payload.iat + tokenDuration;

    // Check for expiration of the token
    if (expiration && expiration < nowInSeconds) {
      throw new PureJWT.PureJWTError("Token has expired", 401);
    }

    // Check if the token is not yet active
    if (payload.nbf && payload.nbf > nowInSeconds) {
      throw new PureJWT.PureJWTError("Token not yet active", 401);
    }

    // Check if audiences match
    if (
      payload.aud &&
      this.allowedAudiences &&
      !PureJWT.arraysConincide(payload.aud, this.allowedAudiences)
    ) {
      throw new PureJWT.PureJWTError("Token has an invalid audience", 401);
    }

    // Check if issuers match
    if (
      payload.iss &&
      this.allowedIssuers &&
      !PureJWT.arraysConincide(payload.iss, this.allowedIssuers)
    ) {
      throw new PureJWT.PureJWTError("Token issuer is invalid", 401);
    }
  }

  // Verifies token's claims
  static preverifyClaims(payload) {
    // Type checking
    if (payload.iat && !Number.isInteger(payload.iat)) {
      throw new PureJWT.PureJWTError(`'iat' must be a Number.`, 500);
    }

    payload.iat = PureJWT.getSeconds(payload.iat);

    if (payload.iat > PureJWT.getSeconds()) {
      throw new PureJWT.PureJWTError(`'iat' cannot be in the future.`, 500);
    }

    if (payload.exp) {
      if (!Number.isInteger(payload.exp)) {
        throw new PureJWT.PureJWTError(`'exp' must be a Number.`, 500);
      } else {
        payload.exp = PureJWT.getSeconds(payload.exp);
      }
    }

    if (payload.nbf && typeof payload.nbf !== "number") {
      if (!Number.isInteger(payload.nbf)) {
        throw new PureJWT.PureJWTError(`'nbf' must be a Number.`, 500);
      } else {
        payload.nbf = PureJWT.getSeconds(payload.nbf);
      }
    }

    if (payload.aud && !PureJWT.isStringOrArrayOfStrings(payload.aud)) {
      throw new PureJWT.PureJWTError(
        `'aud' must be a String or an array of Strings.`,
        500
      );
    }

    if (payload.iss && !PureJWT.isStringOrArrayOfStrings(payload.iss)) {
      throw new PureJWT.PureJWTError(
        `'iss' must be a String or an array of Strings.`,
        500
      );
    }

    return payload;
  }

  // Extracts JWT from request
  static extractJwtFromBearer(token) {
    if (!token)
      throw new PureJWT.PureJWTError("Unauthorized: No token provided", 400);

    const authMatch = token.match(/^(Bearer|Basic|Digest|JWT)\s(.+)/i);

    return authMatch ? authMatch[2] : token;
  }

  static arraysConincide(payloadClaim, optionsClaim) {
    const payloadClaimIdentifiers = Array.isArray(payloadClaim)
      ? payloadClaim
      : [payloadClaim];
    const optionsClaimIdentifiers = Array.isArray(optionsClaim)
      ? optionsClaim
      : [optionsClaim];

    return payloadClaimIdentifiers.some(pci =>
      optionsClaimIdentifiers.some(oci =>
        oci instanceof RegExp ? oci.test(pci) : oci === pci
      )
    );
  }

  static isStringOrArrayOfStrings(value) {
    if (Array.isArray(value)) {
      return value.every(item => typeof item === "string");
    }
    return typeof value === "string";
  }

  // Define the custom error type
  static PureJWTError = class extends Error {
    constructor(message, statusCode, original_error) {
      super(message);
      this.name = "PureJWTError";
      this.message = message;
      this.statusCode = statusCode; // Recommended status code
      this.original_error = original_error;
    }
  };

  // Check if a given timestamp is in seconds
  static isSeconds(timestamp) {
    const threshold = 1000000000000; // 10^12
    return timestamp <= threshold;
  }

  /**
   * Converts the given time in milliseconds to seconds
   * @param {number} ms - Time in milliseconds or seconds
   * @return {number} Time in seconds
   */
  static getSeconds(ms) {
    // Check if the time is already in seconds
    if (ms && PureJWT.isSeconds(ms)) {
      return ms;
    }
    // Convert the time to seconds if it's not already
    else if (ms) {
      return Math.floor(ms / 1000);
    }
    // Default to the current time in seconds if no time is provided
    else {
      return Math.floor(Date.now() / 1000);
    }
  }
}

module.exports = PureJWT;
