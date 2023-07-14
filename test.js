const isBrowser = typeof window !== "undefined";

const request = require("supertest");
const express = require("express");
const cookieParser = require("cookie-parser");
const mocha = require("mocha");
const chai = require("chai");
const crypto = require("crypto");
const PureJWT = require("./purejwt.js");

const FastJWT = require("fast-jwt");

const assert = chai.assert;

function tamperWithToken(originalToken) {
  // Split the token to access and modify the payload
  let [header, payload, signature] = originalToken.split(".");

  // Decode the original payload and modify it
  payload = JSON.parse(Buffer.from(payload, "base64").toString());

  payload.role = "admin";

  // Re-encode the tampered payload
  const tamperedPayloadEncoded = Buffer.from(JSON.stringify(payload)).toString(
    "base64"
  );

  // Construct the tampered token
  const tamperedToken = `${header}.${tamperedPayloadEncoded}.${signature}`;

  return tamperedToken;
}

describe("PureJWT Instantiation", function () {
  let jwt;

  beforeEach(function () {
    jwt = new PureJWT({
      secret: "7a9a66475c4d177",
      allowedIssuers: `https://securetoken.hostluxe.com/project/581753`,
    });
  });

  // Test 1: Can we instantiate PureJWT
  it("should instantiate PureJWT", function () {
    assert.instanceOf(jwt, PureJWT);
  });

  it("should not accept an unknown algorithm", function () {
    try {
      const jwt2 = new PureJWT({
        algorithm: "frosty256",
      });
    } catch (err) {
      assert.instanceOf(err, PureJWT.PureJWTError);
      assert.equal(
        err.message,
        `Invalid algorithm: frosty256. Must be one of: HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, ES512, PS256, PS384, PS512`
      );
    }
  });

  it("should not accept an empty secret", function () {
    try {
      const jwt2 = new PureJWT({
        secret: "",
      });
      assert.fail("Expected an error to be thrown");
    } catch (err) {
      assert.instanceOf(err, PureJWT.PureJWTError);
      assert.equal(
        err.message,
        `A synchronous algorithm must provide a secret.`
      );
    }
  });

  it("should not accept a HS256 algorithm without a secret", function () {
    try {
      const jwt2 = new PureJWT({
        algorithm: "HS256",
      });
      assert.fail("Expected an error to be thrown");
    } catch (err) {
      assert.instanceOf(err, PureJWT.PureJWTError);
      assert.equal(
        err.message,
        `A synchronous algorithm must provide a secret.`
      );
    }
  });

  it("should not accept a numerical secret", function () {
    try {
      const jwt2 = new PureJWT({
        algorithm: "HS256",
        secret: 12345,
      });
      assert.fail("Expected an error to be thrown");
    } catch (err) {
      assert.instanceOf(err, PureJWT.PureJWTError);
      assert.equal(err.message, `The secret must be a string`);
    }
  });

  it("should not accept a RS256 algorithm without any keys", function () {
    try {
      const jwt2 = new PureJWT({
        algorithm: "RS256",
      });
      assert.fail("Expected an error to be thrown");
    } catch (err) {
      assert.instanceOf(err, PureJWT.PureJWTError);
      assert.equal(
        err.message,
        `An asynchronous algorithm must provide a 'publicKey' to verify and also a 'privateKey' to sign.`
      );
    }
  });

  it("should not accept a RS256 algorithm without a publicKey", function () {
    try {
      const { privateKey, publicKey } = PureJWT.generatePublicPrivateKeys();

      const jwt2 = new PureJWT({
        algorithm: "RS256",
        privateKey,
      });
      assert.fail("Expected an error to be thrown");
    } catch (err) {
      assert.instanceOf(err, PureJWT.PureJWTError);
      assert.equal(
        err.message,
        `An asynchronous algorithm must provide a 'publicKey' to verify and also a 'privateKey' to sign.`
      );
    }
  });

  it("should accept a RS256 algorithm with just a publicKey", function () {
    try {
      const { privateKey, publicKey } = PureJWT.generatePublicPrivateKeys();

      const jwt2 = new PureJWT({
        algorithm: "RS256",
        publicKey,
      });

      assert.equal(jwt2.publicKey, publicKey);
    } catch (err) {
      assert.fail("Should not have thrown an error");
    }
  });

  it("should not accept an invalid privateKey", function () {
    try {
      const jwt2 = new PureJWT({
        privateKey: "123",
        publicKey: "",
      });
      assert.fail("Expected an error to be thrown");
    } catch (err) {
      assert.instanceOf(err, PureJWT.PureJWTError);
      assert.equal(err.message, `Cannot infer algorithm from privateKey.`);
    }
  });

  it("should not accept only a publicKey", function () {
    try {
      const jwt2 = new PureJWT({
        publicKey: "123",
      });
      assert.fail("Expected an error to be thrown");
    } catch (err) {
      assert.instanceOf(err, PureJWT.PureJWTError);
      assert.equal(err.message, `Cannot infer algorithm from privateKey.`);
    }
  });
});

describe(`PureJWT Core Functionality`, function () {
  let jwt;

  beforeEach(function () {
    jwt = new PureJWT({
      secret: "7a9a66475c4d177",
      allowedIssuers: `https://securetoken.hostluxe.com/project/581753`,
    });
  });

  afterEach(function () {
    PureJWT.revokedTokens = new Map();
  });

  // Test 2: Generate Secret
  it("should generate a secret key", function () {
    const secret = PureJWT.generateSecret();
    assert.isString(secret);
  });

  // Test 9: Can we generate public and private keys
  it("should generate a pair of multiline RSA keys", function () {
    const { privateKey, publicKey } = PureJWT.generatePublicPrivateKeys();
    assert.isString(privateKey);
    assert.isString(publicKey);
    assert.isTrue(publicKey.includes("\n"));
    assert.isTrue(privateKey.includes("\n"));
  });

  // Test 9: Can we generate public and private keys
  it("should generate a pair of RSA key on a single line", function () {
    const { privateKey, publicKey } = PureJWT.generatePublicPrivateKeys(
      "rsa",
      {},
      true
    );
    assert.isString(privateKey);
    assert.isString(publicKey);
    assert.isFalse(publicKey.includes("\n"));
    assert.isFalse(privateKey.includes("\n"));
  });

  // Test 9: Can we generate public and private keys
  it("should generate a pair of RSA keys with settings applied", function () {
    const { privateKey, publicKey } = PureJWT.generatePublicPrivateKeys("rsa", {
      modulusLength: 3072,
    });
    const algorithm = PureJWT.inferAlgorithmFromKey(privateKey);

    assert.isString(privateKey);
    assert.isString(publicKey);
    assert.equal(algorithm, "RS384");
  });

  it("should not generate keys with an invalid algorithm", function () {
    try {
      const { privateKey, publicKey } =
        PureJWT.generatePublicPrivateKeys("ppp");
    } catch (err) {
      assert.instanceOf(err, PureJWT.PureJWTError);
      assert.equal(
        err.message,
        `The argument 'type' must be a supported key type. Received 'ppp'`
      );
    }
  });

  it("should create a token", function () {
    const payload = { sub: "d2bb6a8d", iss: "mysite.com" };
    const token = jwt.createToken(payload);
    assert.isString(token);
    const parts = token.split(".");
    assert.equal(parts.length, 3);

    // Decode and check the payload
    const decodedHeader = JSON.parse(
      Buffer.from(parts[0], "base64").toString("utf8")
    );

    assert.deepEqual(decodedHeader, {
      alg: "HS256",
      typ: "JWT",
    });

    const decodedPayload = JSON.parse(
      Buffer.from(parts[1], "base64").toString("utf8")
    );

    assert.typeOf(decodedPayload, "object");
    assert.property(decodedPayload, "iat");
    assert.equal(decodedPayload.sub, "d2bb6a8d");
    assert.equal(decodedPayload.iss, "mysite.com");

    const decodedSignature = Buffer.from(parts[2], "base64").toString("utf8");

    assert.isString(decodedSignature);
  });

  it("should not create a token without a private key", function () {
    try {
      const { privateKey, publicKey } = PureJWT.generatePublicPrivateKeys();

      const jwt2 = new PureJWT({
        algorithm: "RS256",
        publicKey,
      });

      jwt2.createToken({ sub: "12345" });

      assert.fail("Expected an error to be thrown");
    } catch (err) {
      assert.instanceOf(err, PureJWT.PureJWTError);
      assert.equal(
        err.message,
        `PureJWT was not instantiated with a 'privateKey' and is unable to createTokens.`
      );
    }
  });

  it("should not create a token with a private key", function () {
    try {
      const { privateKey, publicKey } = PureJWT.generatePublicPrivateKeys();

      const jwt2 = new PureJWT({
        algorithm: "RS256",
        publicKey,
        privateKey,
      });

      const token = jwt2.createToken({ sub: "12345" });
      assert.isString(token);
    } catch (err) {
      assert.fail("Should not throw an error");
    }
  });

  // Test 4: Verify a token
  it("should verify a token", function () {
    const payload = {
      sub: "d2bb6a8d",
      iss: `https://securetoken.hostluxe.com/project/581753`,
    };
    const token = jwt.createToken(payload);
    assert.isString(token);
    const verifiedPayload = jwt.verifyToken(token);

    assert.typeOf(verifiedPayload, "object");
    assert.property(verifiedPayload, "iat");
    assert.equal(verifiedPayload.sub, "d2bb6a8d");
    assert.equal(
      verifiedPayload.iss,
      `https://securetoken.hostluxe.com/project/581753`
    );
  });

  it("should store algorithm in the token header", function () {
    const { privateKey, publicKey } = PureJWT.generatePublicPrivateKeys("rsa");

    const jwt2 = new PureJWT({
      privateKey,
      publicKey,
    });

    const payload = { sub: "d2bb6a8d" };

    const token = jwt2.createToken(payload);

    const decodedHeader = JSON.parse(
      Buffer.from(token.split(".")[0], "base64").toString("utf8")
    );

    assert.equal(decodedHeader.alg, "RS256");
  });

  it("should store payload type in the token header", function () {
    const { privateKey, publicKey } = PureJWT.generatePublicPrivateKeys("rsa");

    const jwt2 = new PureJWT({
      privateKey,
      publicKey,
    });

    const payload = { sub: "d2bb6a8d" };

    const token = jwt2.createToken(payload);

    const decodedHeader = JSON.parse(
      Buffer.from(token.split(".")[0], "base64").toString("utf8")
    );

    assert.equal(decodedHeader.typ, "JWT");
  });

  it("should not create a token without a payload", function () {
    try {
      const token = jwt.createToken();
      assert.fail("Expected an error to be thrown");
    } catch (err) {
      assert.instanceOf(err, PureJWT.PureJWTError);
      assert.equal(
        err.message,
        `Payload must be an object with at least one key.`
      );
    }
  });

  it("should transfer HS tokens in base64url format", function () {
    const payload = {
      name: `�C�|r`,
      iat: 1689351277010,
    };

    const encoded_payload = Buffer.from(JSON.stringify(payload)).toString(
      "base64"
    );

    //encoded_payload = eyJuYW1lIjoi77+9Q++/vXxyIiwiaWF0IjoxNjg5MzUxMjc3MDEwfQ==

    assert.include(encoded_payload, "/");
    assert.include(encoded_payload, "+");
    assert.include(encoded_payload, "=");

    const token = jwt.createToken(payload);

    let signatureB64 = token.split(".")[2];

    const decoded_signature = Buffer.from(signatureB64, "base64url").toString(
      "utf8"
    );
    const b64_encoded_signature =
      Buffer.from(decoded_signature).toString("base64");

    assert.include(b64_encoded_signature, "/");
    assert.include(b64_encoded_signature, "+");
    assert.include(b64_encoded_signature, "=");

    assert.notInclude(token, "/");
    assert.notInclude(token, "+");
    assert.notInclude(token, "=");
  });

  it("should transfer RSA and PS tokens in base64url format", function () {
    const { privateKey, publicKey } = PureJWT.generatePublicPrivateKeys("rsa");

    const jwt2 = new PureJWT({
      privateKey,
      publicKey,
    });

    const payload = {
      name: `�C�|r`,
      iat: 1689351277010,
    };

    const token = jwt2.createToken(payload);

    let signatureB64 = token.split(".")[2];

    const decoded_signature = Buffer.from(signatureB64, "base64url").toString(
      "utf8"
    );
    const b64_encoded_signature =
      Buffer.from(decoded_signature).toString("base64");

    assert.include(b64_encoded_signature, "/");
    assert.include(b64_encoded_signature, "+");

    assert.notInclude(token, "/");
    assert.notInclude(token, "+");
    assert.notInclude(token, "=");
  });

  it("should transfer EC tokens in base64url format", function () {
    const { privateKey, publicKey } = PureJWT.generatePublicPrivateKeys("ec");

    const jwt2 = new PureJWT({
      algorithm: "ES256",
      privateKey,
      publicKey,
    });

    const payload = {
      name: `�C�|r`,
      iat: 1689351277010,
    };

    const token = jwt2.createToken(payload);

    let signatureB64 = token.split(".")[2];

    const decoded_signature = Buffer.from(signatureB64, "base64url").toString(
      "utf8"
    );
    const b64_encoded_signature =
      Buffer.from(decoded_signature).toString("base64");

    assert.include(b64_encoded_signature, "/");
    assert.include(b64_encoded_signature, "+");

    assert.notInclude(token, "/");
    assert.notInclude(token, "+");
    assert.notInclude(token, "=");
  });

  it("should not create a token without a payload", function () {
    try {
      const token = jwt.createToken();
      assert.fail("Expected an error to be thrown");
    } catch (err) {
      assert.instanceOf(err, PureJWT.PureJWTError);
      assert.equal(
        err.message,
        `Payload must be an object with at least one key.`
      );
    }
  });

  it("should automatically detect Algorithm Type from a secret", function () {
    const jwt2 = new PureJWT({ secret: "Hello" });

    assert.equal(jwt2.algorithm, "HS256");
  });

  it("should fail when HS256 payload is tampered with", function () {
    const jwt2 = new PureJWT({
      secret:
        "7a9a66475c4d177392bd8aa4cc1f9145f494d6b2939f9b2c36687e4794ec91e5",
      allowedIssuers: `https://securetoken.hostluxe.com/project/581753`,
    });

    assert.equal(jwt2.algorithm, "HS256");

    // Create the token with original payload
    const originalPayload = { sub: "d2bb6a8d", role: "user" };

    const originalToken = jwt2.createToken(originalPayload);

    const tamperedToken = tamperWithToken(originalToken);

    // Attempt to verify the tampered token
    try {
      jwt2.verifyToken(tamperedToken);
      assert.fail("Expected an error to be thrown");
    } catch (err) {
      // We expect to catch a PureJWTError due to the Token issuer is invalid
      assert.instanceOf(err, PureJWT.PureJWTError);
      assert.equal(err.message, "Token signature is invalid");
    }
  });
});

describe(`Third Party Compatibility`, function () {
  const bitsToModulus = {
    256: 2048,
    384: 3072,
    512: 4096,
  };

  const bitsToCurves = {
    256: "prime256v1",
    384: "secp384r1",
    512: "secp521r1",
  };

  for (const type of ["HS", "ES", "RS", "PS"]) {
    for (const bits of ["256", "384", "512"]) {
      const algorithm = `${type}${bits}`;

      if (type === "HS") {
        const secret = PureJWT.generateSecret();

        it(`${algorithm} - should correcty verify tokens created by 'fast-jwt'`, function () {
          const signSync = FastJWT.createSigner({
            key: secret,
            algorithm,
          });

          const keyJWT = new PureJWT({
            algorithm,
            secret,
          });

          const payload = {
            sub: "d2bb6a8d",
            iat: PureJWT.getSeconds(Date.now()),
          };

          const signature = signSync(payload);

          const returnedPayload = keyJWT.verifyToken(signature);

          assert.deepEqual(payload, returnedPayload);
        });
        it(`${algorithm} - should correcty sign tokens for 'fast-jwt'`, function () {
          const keyJWT = new PureJWT({
            algorithm,
            secret,
          });

          const payload = {
            sub: "d2bb6a8d",
            iat: PureJWT.getSeconds(Date.now()),
          };

          const token = keyJWT.createToken(payload);

          const decode = FastJWT.createDecoder();
          const returnedPayload = decode(token);

          assert.deepEqual(returnedPayload, payload);
        });
      } else {
        let privateKey, publicKey;
        if (type === "RS" || type === "PS") {
          const modulusLength = bitsToModulus[bits];
          ({ privateKey, publicKey } = PureJWT.generatePublicPrivateKeys(
            "rsa",
            {
              modulusLength,
            }
          ));
        } else if (type === "ES") {
          const namedCurve = bitsToCurves[bits];
          ({ privateKey, publicKey } = PureJWT.generatePublicPrivateKeys("ec", {
            namedCurve,
          }));
        }

        it(`${algorithm} - should correcty verify tokens created by 'fast-jwt'`, function () {
          const signSync = FastJWT.createSigner({
            key: privateKey,
            algorithm,
          });

          const keyJWT = new PureJWT({
            privateKey,
            publicKey,
          });

          const payload = {
            sub: "d2bb6a8d",
            iat: PureJWT.getSeconds(Date.now()),
          };

          const signature = signSync(payload);

          const returnedPayload = keyJWT.verifyToken(signature);

          assert.deepEqual(payload, returnedPayload);
        });
        it(`${algorithm} - should correcty sign tokens for 'fast-jwt'`, function () {
          const secret = PureJWT.generateSecret();

          const keyJWT = new PureJWT({
            privateKey,
            publicKey,
          });

          const payload = {
            sub: "d2bb6a8d",
            iat: PureJWT.getSeconds(Date.now()),
          };

          const token = keyJWT.createToken(payload);

          const decode = FastJWT.createDecoder();
          const returnedPayload = decode(token);

          assert.deepEqual(returnedPayload, payload);
        });
      }
    }
  }
});

describe(`'nbf' (Not Before) Claims`, function () {
  let jwt;

  beforeEach(function () {
    jwt = new PureJWT({
      secret: "7a9a66475c4d177",
      allowedIssuers: `https://securetoken.hostluxe.com/project/581753`,
      allowedAudiences: "https://microservice.myenterprisesolution.com",
    });
  });

  it(`should accept a numerical 'nbf' claim`, function () {
    const nbf = Math.floor(Date.now() / 1000);
    const payload = { sub: "d2bb6a8d", nbf };
    const token = jwt.createToken(payload);
    const returnedPayload = jwt.verifyToken(token);
    assert.equal(returnedPayload.nbf, payload.nbf);
  });

  it(`should refuse a non-numerical 'nbf' claim`, function () {
    const payload = { sub: "d2bb6a8d", nbf: "a string" };

    try {
      const token = jwt.createToken(payload);
      assert.fail("Expected an error to be thrown");
    } catch (err) {
      assert.instanceOf(err, PureJWT.PureJWTError);
      assert.equal(err.message, `'nbf' must be a Number.`);
    }
  });

  it(`should refuse an inactive token`, function () {
    const nbf = Math.floor(Date.now() / 1000) + 10000;
    const payload = { sub: "d2bb6a8d", nbf };
    const token = jwt.createToken(payload);

    try {
      const payload = jwt.verifyToken(token);
      assert.fail("Expected an error to be thrown");
    } catch (err) {
      assert.instanceOf(err, PureJWT.PureJWTError);
      assert.equal(err.message, `Token not yet active`);
    }
  });
});

describe(`'iss' (Issuer) claims`, function () {
  let jwt;

  beforeEach(function () {
    jwt = new PureJWT({
      secret: "7a9a66475c4d177",
      allowedIssuers: `https://securetoken.hostluxe.com/project/581753`,
      allowedAudiences: "https://microservice.myenterprisesolution.com",
    });
  });

  it(`should accept a string 'iss'`, function () {
    const payload = {
      sub: "d2bb6a8d",
      iss: `https://securetoken.hostluxe.com/project/581753`,
      role: "user",
    };
    const token = jwt.createToken(payload);
    const returnedPayload = jwt.verifyToken(token);
    assert.equal(returnedPayload.iss, payload.iss);
  });

  it(`should accept a string array 'iss'`, function () {
    const iss = [
      `https://securetoken.hostluxe.com/project/581753`,
      "https://chat.myenterprisesolution.com",
    ];
    const payload = { sub: "d2bb6a8d", iss };
    const token = jwt.createToken(payload);
    const returnedPayload = jwt.verifyToken(token);
    assert.deepEqual(returnedPayload.iss, iss);
  });

  it(`should reject a non-string 'iss'`, function () {
    const payload = { sub: "d2bb6a8d", iss: 123 };

    try {
      const token = jwt.createToken(payload);
      assert.fail("Expected an error to be thrown");
    } catch (err) {
      assert.instanceOf(err, PureJWT.PureJWTError);
      assert.equal(
        err.message,
        `'iss' must be a String or an array of Strings.`
      );
    }
  });

  it(`should refuse a non-string array 'iss'`, function () {
    const iss = [`https://securetoken.hostluxe.com/project/581753`, 123];
    const payload = { sub: "d2bb6a8d", iss };
    try {
      const token = jwt.createToken(payload);
      assert.fail("Expected an error to be thrown");
    } catch (err) {
      assert.instanceOf(err, PureJWT.PureJWTError);
      assert.equal(
        err.message,
        `'iss' must be a String or an array of Strings.`
      );
    }
  });

  it(`should accept a valid 'iss'`, function () {
    const payload = {
      sub: "d2bb6a8d",
      iss: `https://securetoken.hostluxe.com/project/581753`,
      role: "user",
    };
    const token = jwt.createToken(payload);
    const returnedPayload = jwt.verifyToken(token);
    assert.equal(returnedPayload.iss, payload.iss);
  });

  it(`should accept one of many valid 'allowedIssuers'`, function () {
    const jwt2 = new PureJWT({
      secret: "7a9a66475c4d177",
      allowedIssuers: [
        `https://securetoken.hostluxe.com/project/581753`,
        "https://client.myretailapp.com",
      ],
    });

    const payload = { sub: "d2bb6a8d", iss: "https://client.myretailapp.com" };
    const token = jwt2.createToken(payload);
    const returnedPayload = jwt2.verifyToken(token);
    assert.equal(returnedPayload.iss, payload.iss);
  });

  it(`should accept one of many valid 'iss'`, function () {
    const jwt2 = new PureJWT({
      secret: "7a9a66475c4d177",
      allowedIssuers: "https://client.myretailapp.com",
    });

    const payload = {
      sub: "d2bb6a8d",
      iss: ["https://client.myretailapp.com", "a-third-entity.com"],
    };
    const token = jwt2.createToken(payload);
    const returnedPayload = jwt2.verifyToken(token);
    assert.deepEqual(returnedPayload.iss, payload.iss);
  });

  it(`should accept a token with a 'iss' and 'allowedIssuers' overlap`, function () {
    const jwt2 = new PureJWT({
      secret: "7a9a66475c4d177",
      allowedIssuers: [
        `https://securetoken.hostluxe.com/project/581753`,
        "https://client.myretailapp.com",
      ],
    });

    const payload = {
      sub: "d2bb6a8d",
      iss: ["https://client.myretailapp.com", "a-third-entity.com"],
    };
    const token = jwt2.createToken(payload);
    const returnedPayload = jwt2.verifyToken(token);
    assert.deepEqual(returnedPayload.iss, payload.iss);
  });

  it(`should reject a token without a 'iss' and 'allowedIssuers' overlap`, function () {
    const jwt2 = new PureJWT({
      secret: "7a9a66475c4d177",
      allowedIssuers: [
        `https://securetoken.hostluxe.com/project/581753`,
        "https://client.myretailapp.com",
      ],
    });

    const payload = {
      sub: "d2bb6a8d",
      iss: ["api.myhealthcareapp.com", "mysocialnetwork.com"],
    };
    const token = jwt2.createToken(payload);
    try {
      const returnedPayload = jwt2.verifyToken(token);
      assert.fail("Expected an error to be thrown");
    } catch (err) {
      assert.instanceOf(err, PureJWT.PureJWTError);
      assert.equal(err.message, "Token issuer is invalid");
    }
  });

  it(`should reject an invalid 'iss'`, function () {
    const payload = { sub: "d2bb6a8d", iss: "some-issuer" };
    const token = jwt.createToken(payload);
    try {
      jwt.verifyToken(token);
      assert.fail("Expected an error to be thrown");
    } catch (err) {
      // We expect to catch a PureJWTError due to the Token issuer is invalid
      assert.instanceOf(err, PureJWT.PureJWTError);
      assert.equal(err.message, "Token issuer is invalid");
    }
  });

  it(`should accept any 'iss' when no 'allowedIssuers' is specified in options`, function () {
    const jwt2 = new PureJWT({
      secret: "hello",
    });

    const payload = { sub: "d2bb6a8d", iss: "some-issuer" };

    const token = jwt2.createToken(payload);

    const returnedPayload = jwt2.verifyToken(token);

    assert.equal(returnedPayload.iss, "some-issuer");
  });
});

describe(`'aud' (Audience) claims`, function () {
  let jwt;

  beforeEach(function () {
    jwt = new PureJWT({
      secret: "7a9a66475c4d177",
      allowedIssuers: `https://securetoken.hostluxe.com/project/581753`,
      allowedAudiences: "https://microservice.myenterprisesolution.com",
    });
  });

  it(`should accept a string 'aud' (Audience)`, function () {
    const payload = {
      sub: "d2bb6a8d",
      aud: "https://microservice.myenterprisesolution.com",
    };
    const token = jwt.createToken(payload);
    const returnedPayload = jwt.verifyToken(token);
    assert.equal(returnedPayload.aud, payload.aud);
  });

  it(`should accept a string array 'aud'`, function () {
    const aud = [
      "https://microservice.myenterprisesolution.com",
      "https://chat.myenterprisesolution.com",
    ];
    const payload = { sub: "d2bb6a8d", aud };
    const token = jwt.createToken(payload);
    const returnedPayload = jwt.verifyToken(token);
    assert.deepEqual(returnedPayload.aud, aud);
  });

  it(`should refuse a non-string 'aud'`, function () {
    const payload = { sub: "d2bb6a8d", aud: 123 };

    try {
      const token = jwt.createToken(payload);
      assert.fail("Expected an error to be thrown");
    } catch (err) {
      assert.instanceOf(err, PureJWT.PureJWTError);
      assert.equal(
        err.message,
        `'aud' must be a String or an array of Strings.`
      );
    }
  });

  it(`should refuse a non-string array 'aud'`, function () {
    const aud = ["https://microservice.myenterprisesolution.com", 123];
    const payload = { sub: "d2bb6a8d", aud };
    try {
      const token = jwt.createToken(payload);
      assert.fail("Expected an error to be thrown");
    } catch (err) {
      assert.instanceOf(err, PureJWT.PureJWTError);
      assert.equal(
        err.message,
        `'aud' must be a String or an array of Strings.`
      );
    }
  });

  // Test 11: Validate Audience claim
  it(`should accept a valid 'aud'`, function () {
    const payload = {
      sub: "d2bb6a8d",
      aud: "https://microservice.myenterprisesolution.com",
    };
    const token = jwt.createToken(payload);
    const returnedPayload = jwt.verifyToken(token);
    assert.equal(returnedPayload.aud, payload.aud);
  });

  // Test 12: Reject Invalid Audience
  it(`should reject an invalid 'aud'`, function () {
    const payload = { sub: "d2bb6a8d", aud: "invalid-audience" };
    const token = jwt.createToken(payload);
    try {
      jwt.verifyToken(token);
      assert.fail("Expected an error to be thrown");
    } catch (err) {
      assert.instanceOf(err, PureJWT.PureJWTError);
      assert.equal(err.message, "Token has an invalid audience");
    }
  });

  it(`should accept one of many valid 'allowedAudiences'`, function () {
    const jwt2 = new PureJWT({
      secret: "7a9a66475c4d177",
      allowedAudiences: ["premium-api", "basic-api"],
    });

    const payload = { sub: "d2bb6a8d", aud: "basic-api" };
    const token = jwt2.createToken(payload);
    const returnedPayload = jwt2.verifyToken(token);
    assert.equal(returnedPayload.iss, payload.iss);
  });

  it(`should accept one of many valid 'aud'`, function () {
    const jwt2 = new PureJWT({
      secret: "7a9a66475c4d177",
      allowedAudiences: "basic-api",
    });

    const payload = { sub: "d2bb6a8d", aud: ["basic-api", "mid-tier-api"] };
    const token = jwt2.createToken(payload);
    const returnedPayload = jwt2.verifyToken(token);
    assert.deepEqual(returnedPayload.aud, payload.aud);
  });

  it(`should accept a token with a 'aud' and 'allowedAudiences' overlap`, function () {
    const jwt2 = new PureJWT({
      secret: "7a9a66475c4d177",
      allowedAudiences: ["premium-api", "basic-api"],
    });

    const payload = { sub: "d2bb6a8d", aud: ["basic-api", "mid-tier-api"] };
    const token = jwt2.createToken(payload);
    const returnedPayload = jwt2.verifyToken(token);
    assert.deepEqual(returnedPayload.aud, payload.aud);
  });

  it(`should reject a token without a 'aud' and 'allowedAudiences' overlap`, function () {
    const jwt2 = new PureJWT({
      secret: "7a9a66475c4d177",
      allowedAudiences: ["premium-api", "basic-api"],
    });

    const payload = {
      sub: "d2bb6a8d",
      aud: ["mid-tier-api", "everything-api"],
    };
    const token = jwt2.createToken(payload);
    try {
      const returnedPayload = jwt2.verifyToken(token);
      assert.fail("Expected an error to be thrown");
    } catch (err) {
      assert.instanceOf(err, PureJWT.PureJWTError);
      assert.equal(err.message, "Token has an invalid audience");
    }
  });

  it(`should accept any 'aud' when no 'allowedAudiences' is specified in options`, function () {
    const jwt2 = new PureJWT({
      secret: "hello",
    });

    const payload = { sub: "d2bb6a8d", aud: "some-issuer" };

    const token = jwt2.createToken(payload);

    const returnedPayload = jwt2.verifyToken(token);

    assert.equal(returnedPayload.aud, "some-issuer");
  });
});

describe(`'iat' (Issued At) Claims`, function () {
  let jwt;

  beforeEach(function () {
    jwt = new PureJWT({
      secret: "7a9a66475c4d177",
      allowedIssuers: `https://securetoken.hostluxe.com/project/581753`,
      allowedAudiences: "https://microservice.myenterprisesolution.com",
    });
  });

  it(`should set a default 'iat' to now`, function () {
    const iat = Math.floor(Date.now() / 1000);
    const payload = { sub: "d2bb6a8d" };
    const token = jwt.createToken(payload);
    const returnedPayload = jwt.verifyToken(token);
    assert.equal(returnedPayload.iat, iat);
  });

  it(`should accept a numerical 'iat'`, function () {
    const iat = Math.floor(Date.now() / 1000) - 100;
    const payload = { sub: "d2bb6a8d", iat };
    const token = jwt.createToken(payload);
    const returnedPayload = jwt.verifyToken(token);
    assert.equal(returnedPayload.iat, payload.iat);
  });

  it(`should refuse a non-numerical 'iat'`, function () {
    const payload = { sub: "d2bb6a8d", iat: "a string" };

    try {
      const token = jwt.createToken(payload);
      assert.fail("Expected an error to be thrown");
    } catch (err) {
      assert.instanceOf(err, PureJWT.PureJWTError);
      assert.equal(err.message, `'iat' must be a Number.`);
    }
  });

  // // Test 18: Reject JWT with past expiry time
  it(`should accept an unexpired 'iat'`, function () {
    const payload = { sub: "d2bb6a8d", iat: Math.floor(Date.now() / 1000) };
    const token = jwt.createToken(payload);

    const returnedPayload = jwt.verifyToken(token);
    assert.equal(returnedPayload.sub, payload.sub);
    assert.equal(returnedPayload.iat, payload.iat);
  });

  it(`should reject a future 'iat'`, function () {
    const payload = {
      sub: "d2bb6a8d",
      iat: Math.floor(Date.now() / 1000) + 60 * 60,
    };

    try {
      const token = jwt.createToken(payload);
      assert.fail("Expected an error to be thrown");
    } catch (err) {
      assert.instanceOf(err, PureJWT.PureJWTError);
      assert.equal(err.message, `'iat' cannot be in the future.`);
    }
  });

  it(`should refuse an expired 'iat'`, function () {
    const iat = Math.floor(Date.now() / 1000) - 25 * 60 * 60;
    const payload = { sub: "d2bb6a8d", iat };
    const token = jwt.createToken(payload);
    try {
      const token_payload = jwt.verifyToken(token);
      assert.fail("Expected an error to be thrown");
    } catch (err) {
      assert.instanceOf(err, PureJWT.PureJWTError);
      assert.equal(err.message, "Token has expired");
    }
  });

  it(`should refuse a token past it's issue duration`, function () {
    const jwt2 = new PureJWT({
      secret: "7a9a66475c4d177",
      allowedIssuers: `https://securetoken.hostluxe.com/project/581753`,
      durationInMinutes: -1,
    });

    const payload = { sub: "d2bb6a8d" };
    const token = jwt2.createToken(payload);
    try {
      const token_payload = jwt2.verifyToken(token);
      assert.fail("Expected an error to be thrown");
    } catch (err) {
      assert.instanceOf(err, PureJWT.PureJWTError);
      assert.equal(err.message, "Token has expired");
    }
  });
});

describe(`'exp' (Expiration) Claims`, function () {
  let jwt;

  beforeEach(function () {
    jwt = new PureJWT({
      secret: "7a9a66475c4d177",
      allowedIssuers: `https://securetoken.hostluxe.com/project/581753`,
      allowedAudiences: "https://microservice.myenterprisesolution.com",
    });
  });

  it(`should accept a numerical 'exp'`, function () {
    const exp = Math.floor(Date.now() / 1000) + 100;
    const payload = { sub: "d2bb6a8d", exp };
    const token = jwt.createToken(payload);
    const returnedPayload = jwt.verifyToken(token);
    assert.equal(returnedPayload.exp, payload.exp);
  });

  it(`should refuse a non-numerical 'exp'`, function () {
    const payload = { sub: "d2bb6a8d", exp: "a string" };

    try {
      const token = jwt.createToken(payload);
      assert.fail("Expected an error to be thrown");
    } catch (err) {
      assert.instanceOf(err, PureJWT.PureJWTError);
      assert.equal(err.message, `'exp' must be a Number.`);
    }
  });

  it(`should accept an unexpired 'exp'`, function () {
    const exp = Math.floor(Date.now() / 1000) + 60 * 60;
    const payload = { sub: "d2bb6a8d", exp };
    const token = jwt.createToken(payload);
    const returnedPayload = jwt.verifyToken(token);
    assert.equal(returnedPayload.exp, payload.exp);
  });

  // Test 6: Should throw error for expired token
  it(`should refuse an expired 'exp'`, function () {
    const exp = Date.now() - 1000;
    const payload = { sub: "d2bb6a8d", exp };
    const token = jwt.createToken(payload);
    try {
      const token_payload = jwt.verifyToken(token);
      assert.fail("Expected an error to be thrown");
    } catch (err) {
      assert.instanceOf(err, PureJWT.PureJWTError);
      assert.equal(err.message, "Token has expired");
    }
  });

  // Test 16: Reject Invalid Issue Time
  it(`should prioritize 'exp' over 'iss'`, function () {
    const iat = Math.floor(Date.now() / 1000) - 25 * 60 * 60;
    const exp = Math.floor(Date.now() / 1000) + 1 * 60 * 60;
    const payload = { sub: "d2bb6a8d", iat, exp };
    const token = jwt.createToken(payload);
    const returnedPayload = jwt.verifyToken(token);
    assert.equal(returnedPayload.exp, exp);
  });
});

describe("RSA PureJWT", function () {
  it("should automatically detect Algorithm Type from a RS256 privateKey", function () {
    const { privateKey, publicKey } = PureJWT.generatePublicPrivateKeys("rsa");

    const jwt2 = new PureJWT({ privateKey, publicKey });

    assert.equal(jwt2.algorithm, "RS256");
  });

  it("should automatically detect Algorithm Type from a RS384 privateKey", function () {
    const { privateKey, publicKey } = PureJWT.generatePublicPrivateKeys("rsa", {
      modulusLength: 3072,
    });

    const jwt2 = new PureJWT({ privateKey, publicKey });

    assert.equal(jwt2.algorithm, "RS384");
  });

  it("should automatically detect Algorithm Type from a RS512 privateKey", function () {
    const { privateKey, publicKey } = PureJWT.generatePublicPrivateKeys("rsa", {
      modulusLength: 4096,
    });

    const jwt2 = new PureJWT({ privateKey, publicKey });

    assert.equal(jwt2.algorithm, "RS512");
  });

  // Test 14: JWT signing with RSA
  it("should successfully sign the JWT with RS256", function () {
    const { privateKey, publicKey } = PureJWT.generatePublicPrivateKeys("rsa");
    const jwt2 = new PureJWT({
      privateKey,
      publicKey,
      allowedIssuers: "myapp",
    });
    const payload = { sub: "1234567890", name: "John Doe" };
    const token = jwt2.createToken(payload);
    assert.isString(token);
    assert.equal(token.split(".").length, 3);
  });

  // Test 15: Signature verification with public key
  it("should verify signature with the public key", function () {
    const { privateKey, publicKey } = PureJWT.generatePublicPrivateKeys("rsa");
    const jwt2 = new PureJWT({
      privateKey,
      publicKey,
      allowedIssuers: "myapp",
    });

    const payload = { sub: "1234567890", name: "John Doe", iss: "myapp" };
    const token = jwt2.createToken(payload);
    assert.isString(token);
    assert.equal(token.split(".").length, 3);

    const verified = jwt2.verifyToken(token);

    assert.typeOf(verified, "object");
    assert.property(verified, "iat");
    assert.equal(verified.sub, payload.sub);
    assert.equal(verified.name, payload.name);
    assert.equal(verified.iss, payload.iss);
  });

  // Test 16: Verification failure for tampered signature
  it("should throw error when signature is tampered", function () {
    const { privateKey, publicKey } = PureJWT.generatePublicPrivateKeys("rsa");
    const jwt2 = new PureJWT({
      privateKey,
      publicKey,
      allowedIssuers: "myapp",
    });

    // Create the token with original payload
    const originalPayload = {
      sub: "1234567890",
      name: "John Doe",
      role: "user",
    };

    const originalToken = jwt2.createToken(originalPayload);

    const tamperedToken = tamperWithToken(originalToken);

    assert.throws(() => {
      jwt2.verifyToken(tamperedToken, publicKey);
    }, PureJWT.PureJWTError);
  });
});

describe("ES PureJWT", function () {
  it("should automatically detect Algorithm Type from a ES256 privateKey", function () {
    const { privateKey, publicKey } = PureJWT.generatePublicPrivateKeys("ec", {
      namedCurve: "prime256v1",
    });

    const jwt2 = new PureJWT({ privateKey, publicKey });

    assert.equal(jwt2.algorithm, "ES256");
  });

  it("should automatically detect Algorithm Type from a ES384 privateKey", function () {
    const { privateKey, publicKey } = PureJWT.generatePublicPrivateKeys("ec", {
      namedCurve: "secp384r1",
    });

    const jwt2 = new PureJWT({ privateKey, publicKey });

    assert.equal(jwt2.algorithm, "ES384");
  });

  it("should automatically detect Algorithm Type from a ES512 privateKey", function () {
    const { privateKey, publicKey } = PureJWT.generatePublicPrivateKeys("ec", {
      namedCurve: "secp521r1",
    });

    const jwt2 = new PureJWT({ privateKey, publicKey });

    assert.equal(jwt2.algorithm, "ES512");
  });

  // Test 14: JWT signing with RSA
  it("should successfully sign the JWT with ES256", function () {
    const { privateKey, publicKey } = PureJWT.generatePublicPrivateKeys("ec", {
      namedCurve: "prime256v1",
    });
    const jwt2 = new PureJWT({
      privateKey,
      publicKey,
      allowedIssuers: "myapp",
    });
    const payload = { sub: "1234567890", name: "John Doe" };
    const token = jwt2.createToken(payload);
    assert.isString(token);
    assert.equal(token.split(".").length, 3);
  });

  // Test 15: Signature verification with public key
  it("should verify signature with the public key", function () {
    const { privateKey, publicKey } = PureJWT.generatePublicPrivateKeys("ec", {
      namedCurve: "prime256v1",
    });
    const jwt2 = new PureJWT({
      privateKey,
      publicKey,
      allowedIssuers: "myapp",
    });
    const payload = { sub: "1234567890", name: "John Doe", iss: "myapp" };
    const token = jwt2.createToken(payload);
    assert.isString(token);
    assert.equal(token.split(".").length, 3);

    const verified = jwt2.verifyToken(token);
    assert.typeOf(verified, "object");
    assert.property(verified, "iat");
    assert.equal(verified.sub, payload.sub);
    assert.equal(verified.name, payload.name);
    assert.equal(verified.iss, payload.iss);
  });

  // Test 16: Verification failure for tampered signature
  it("should throw error when signature is tampered", function () {
    const { privateKey, publicKey } = PureJWT.generatePublicPrivateKeys("ec", {
      namedCurve: "prime256v1",
    });
    const jwt2 = new PureJWT({
      privateKey,
      publicKey,
      allowedIssuers: "myapp",
    });

    // Create the token with original payload
    const originalPayload = {
      sub: "1234567890",
      name: "John Doe",
      role: "user",
    };

    const originalToken = jwt2.createToken(originalPayload);

    assert.isString(originalToken);
    assert.equal(originalToken.split(".").length, 3);

    const tamperedToken = tamperWithToken(originalToken);

    assert.throws(() => {
      jwt2.verifyToken(tamperedToken, publicKey);
    }, PureJWT.PureJWTError);
  });
});

describe("PS PureJWT", function () {
  it("should automatically detect Algorithm Type from a PS256 privateKey", function () {
    const { privateKey, publicKey } = PureJWT.generatePublicPrivateKeys("rsa");

    const jwt2 = new PureJWT({ privateKey, publicKey, algorithm: "PS256" });

    assert.equal(jwt2.algorithm, "PS256");
  });

  it("should automatically detect Algorithm Type from a PS384 privateKey", function () {
    const { privateKey, publicKey } = PureJWT.generatePublicPrivateKeys("rsa", {
      modulusLength: 3072,
    });

    const jwt2 = new PureJWT({ privateKey, publicKey, algorithm: "PS384" });

    assert.equal(jwt2.algorithm, "PS384");
  });

  it("should automatically detect Algorithm Type from a PS512 privateKey", function () {
    const { privateKey, publicKey } = PureJWT.generatePublicPrivateKeys("rsa", {
      modulusLength: 4096,
    });

    const jwt2 = new PureJWT({ privateKey, publicKey, algorithm: "PS512" });

    assert.equal(jwt2.algorithm, "PS512");
  });

  // Test 14: JWT signing with RSA
  it("should successfully sign the JWT with PS256", function () {
    const { privateKey, publicKey } = PureJWT.generatePublicPrivateKeys("rsa");
    const jwt2 = new PureJWT({
      privateKey,
      publicKey,
      algorithm: "PS256",
      allowedIssuers: "myapp",
    });
    const payload = { sub: "1234567890", name: "John Doe" };
    const token = jwt2.createToken(payload);
    assert.isString(token);
    assert.equal(token.split(".").length, 3);
  });

  // Test 15: Signature verification with public key
  it("should verify signature with the public key", function () {
    const { privateKey, publicKey } = PureJWT.generatePublicPrivateKeys("rsa");
    const jwt2 = new PureJWT({
      privateKey,
      publicKey,
      algorithm: "PS256",
      allowedIssuers: "myapp",
    });
    const payload = { sub: "1234567890", name: "John Doe", iss: "myapp" };
    const token = jwt2.createToken(payload);
    assert.isString(token);
    assert.equal(token.split(".").length, 3);

    const verified = jwt2.verifyToken(token);
    assert.typeOf(verified, "object");
    assert.property(verified, "iat");
    assert.equal(verified.sub, payload.sub);
    assert.equal(verified.name, payload.name);
    assert.equal(verified.iss, payload.iss);
  });

  // Test 16: Verification failure for tampered signature
  it("should throw error when signature is tampered", function () {
    const { privateKey, publicKey } = PureJWT.generatePublicPrivateKeys("rsa");
    const jwt2 = new PureJWT({
      privateKey,
      publicKey,
      algorithm: "PS256",
      allowedIssuers: "myapp",
    });

    // Create the token with original payload
    const originalPayload = {
      sub: "1234567890",
      name: "John Doe",
      role: "user",
    };

    const originalToken = jwt2.createToken(originalPayload);

    assert.isString(originalToken);
    assert.equal(originalToken.split(".").length, 3);

    const tamperedToken = tamperWithToken(originalToken);

    assert.throws(() => {
      jwt2.verifyToken(tamperedToken, publicKey);
    }, PureJWT.PureJWTError);
  });
});

// describe('Test the PureJWT middleware', () => {
//   let token

//   const app = express()
//   app.use(cookieParser())
//   app.use(express.json())

//   const jwt2 = new PureJWT({ algorithm: 'HS256', secret: 'your_secret' })
//   const payload = { name: 'John Doe' }

//   app.get('/dummy', jwt2.getTokenPayload('token'), (req, res) => {
//     res.json({ message: 'success' })
//   })

//   app.post('/dummy', jwt2.getTokenPayload('token'), (req, res) => {
//     res.json({ message: 'success' })
//   })

//   app.post('/custom', jwt2.getTokenPayload('custom'), (req, res) => {
//     res.json({ message: 'success' })
//   })

//   app.get('/custom', jwt2.getTokenPayload('custom'), (req, res) => {
//     res.json({ message: 'success' })
//   })

//   before(() => {
//     token = jwt2.createToken(payload)
//   })

//   it('should succeed with a valid token', (done) => {
//     request(app)
//       .get('/dummy')
//       .set('Authorization', `Bearer ${token}`)
//       .end((err, res) => {
//         assert.equal(res.statusCode, 200)
//         assert.property(res.body, 'message')
//         assert.equal(res.body.message, 'success')
//         done()
//       })
//   })

//   it('should set the payload of a valid token on req.token', (done) => {

//     app.get('/payload', jwt2.getTokenPayload('token'), (req, res) => {
//       assert.property(req, 'payload')
//       assert.property(req.payload, 'name')
//       assert.property(req.payload, 'iat')
//       assert.equal(req.payload.name, 'John Doe')
//       res.json({ message: 'success' })
//     })

//     request(app)
//       .get('/payload')
//       .set('Authorization', `Bearer ${token}`)
//       .end((err, res) => {
//         assert.equal(res.statusCode, 200)
//         assert.property(res.body, 'message')
//         assert.equal(res.body.message, 'success')
//         done()
//       })
//   })

//   it('should fail without a token', (done) => {
//     request(app)
//       .get('/dummy')
//       .expect(400)
//       .end((err, res) => {
//         assert.equal(res.body.message, 'Unauthorized: No token provided')
//         done()
//       })
//   })

//   it('should fail with a token in the wrong place', (done) => {
//     request(app)
//       .get('/dummy')
//       .set('my-token', `Bearer ${token}`)
//       .expect(400)
//       .end((err, res) => {
//         assert.equal(res.body.message, 'Unauthorized: No token provided')
//         done()
//       })
//   })

//   it('should fail with an unapproved token prefix', (done) => {
//     request(app)
//       .get('/dummy')
//       .set('Authorization', `Lama ${token}`)
//       .expect(400)
//       .end((err, res) => {
//         assert.equal(res.body.message, 'Token cannot be parsed.')
//         done()
//       })
//   })

//   it('should fail with an invalid token', (done) => {
//     request(app)
//       .get('/dummy')
//       .set('Authorization', `Bearer ${tamperWithToken(token)}`)
//       .expect(401)
//       .end((err, res) => {
//         assert.equal(res.body.message, 'Token signature is invalid')
//         done()
//       })
//   })

//   it(`should fail with an expired token using 'iat'`, (done) => {

//     const pastToken = jwt2.createToken({ sub: '123', iat: PureJWT.getSeconds() - (48 * 60 * 60) })

//     request(app)
//       .get('/dummy')
//       .set('Authorization', `Bearer ${pastToken}`)
//       .expect(401)
//       .end((err, res) => {
//         assert.equal(res.body.message, 'Token has expired')
//         done()
//       })
//   })

//   it(`should fail with an expired token using 'exp'`, (done) => {

//     const pastToken = jwt2.createToken({ sub: '123', exp: PureJWT.getSeconds() - (60) })

//     request(app)
//       .get('/dummy')
//       .set('Authorization', `Bearer ${pastToken}`)
//       .expect(401)
//       .end((err, res) => {
//         assert.equal(res.body.message, 'Token has expired')
//         done()
//       })
//   })

//   it('should succeed with a token in the Authorization header', (done) => {
//     request(app)
//       .get('/dummy')
//       .set('Authorization', `Bearer ${token}`)
//       .expect(200)
//       .end((err, res) => {
//         assert.equal(res.body.message, 'success')
//         done()
//       })
//   })

//   it('should succeed with a token in a custom header', (done) => {

//     request(app)
//       .get('/dummy')
//       .set('token', token)
//       .expect(200)
//       .end((err, res) => {
//         assert.equal(res.body.message, 'success')
//         done()
//       })
//   })

//   it('should succeed with a token in a cookie', (done) => {
//     request(app)
//       .get('/dummy')
//       .set('Cookie', `token=${token}`)
//       .expect(200)
//       .end((err, res) => {
//         assert.equal(res.body.message, 'success')
//         done()
//       })
//   })

//   it('should succeed with a token in the body', (done) => {
//     request(app)
//       .post('/dummy')
//       .set('Content-Type', 'application/json')
//       .send({ token: token })
//       .expect(200)
//       .end((err, res) => {
//         assert.equal(res.body.message, 'success')
//         done()
//       })
//   })

//   it('should succeed with a token in the query string', (done) => {
//     const encodedToken = encodeURIComponent(token)

//     request(app)
//       .get(`/dummy?token=${encodedToken}`)
//       .expect(200)
//       .end((err, res) => {
//         assert.equal(res.body.message, 'success')
//         done()
//       })
//   })

//   it('should succeed with a token in a custom field name in a header', (done) => {

//     request(app)
//       .get('/custom')
//       .set('custom', token)
//       .expect(200)
//       .end((err, res) => {
//         assert.equal(res.body.message, 'success')
//         done()
//       })
//   })

//   it('should succeed with a token in a custom field name in a cookie', (done) => {
//     request(app)
//       .get('/custom')
//       .set('Cookie', `custom="Digest ${token}"`)
//       .expect(200)
//       .end((err, res) => {
//         assert.equal(res.body.message, 'success')
//         done()
//       })
//   })

//   it('should succeed with a token in a custom field name in the body', (done) => {
//     request(app)
//       .post('/custom')
//       .set('Content-Type', 'application/json')
//       .send({ custom: `Basic ${token}` })
//       .expect(200)
//       .end((err, res) => {
//         assert.equal(res.body.message, 'success')
//         done()
//       })
//   })

//   it('should succeed with a token in a custom field name in the query string', (done) => {
//     const encodedToken = encodeURIComponent(token)

//     request(app)
//       .get(`/custom?custom=${encodedToken}`)
//       .expect(200)
//       .end((err, res) => {
//         assert.equal(res.body.message, 'success')
//         done()
//       })
//   })
// })
