# PureJWT

PureJWT is a featherweight and independent library designed to facilitate the creation and verification of JSON Web Tokens (JWT). Removing any reliance on third-party libraries, it ensures simplicity, security, and provides complete control over JWT operations.

From key generation to token signature verification, PureJWT encompasses it all in a simple, straightforward manner. The library allows for the use of both symmetric (HMAC) and asymmetric (RSA, RSA-PSS, ECDSA) cryptographic algorithms.

## Installation

Install PureJWT using npm:

```bash
npm install --save purejwt
```

## Features

- Supports for a wide range of algorithms. Including:

| Algorithm | Description          |
| --------- | -------------------- |
| HS256     | HMAC with SHA-256    |
| HS384     | HMAC with SHA-384    |
| HS512     | HMAC with SHA-512    |
| RS256     | RSA with SHA-256     |
| RS384     | RSA with SHA-384     |
| RS512     | RSA with SHA-512     |
| ES256     | ECDSA with SHA-256   |
| ES384     | ECDSA with SHA-384   |
| ES512     | ECDSA with SHA-512   |
| PS256     | RSA-PSS with SHA-256 |
| PS384     | RSA-PSS with SHA-384 |
| PS512     | RSA-PSS with SHA-512 |

- Facilitates generation of a secret for HMAC algorithms.
- Generates public and private keys for RSA, RSA-PSS, and ECDSA algorithms.
- Encoding, decoding, signing, and verification of JWTs.
- Automatic algorithm detection based on the provided keys.
- Control over token expiration.
- Flexibility in setting acceptable issuers and audiences for token verification.
- A custom error type, PureJWT.PureJWTError, for precise error handling.

## Quick Start Guide

Begin by importing PureJWT:

```javascript
const PureJWT = require("purejwt");
```

Create a secure secret for HMAC algorithms:

```javascript
console.log(`SECRET="${PureJWT.generateSecret()}"`);
```

Use this secret to instantiate PureJWT:

```javascript
require("dotenv").config(); // Install with npm install --save dotenv

const jwt = new PureJWT({
  secret: process.env.SECRET,
});
```

Generate and store private/public keys as secure environment variables. Use these keys to initialize PureJWT without needing to specify the algorithm (except for `PS256`, `PS384`, or `PS512`). With public/private keys, the appropriate algorithm is automatically detected.

```javascript
const jwt = new PureJWT({
  privateKey: process.env.PRIVATE_KEY,
  publicKey: process.env.PUBLIC_KEY,
});
```

During initialization, you can specify options such as token lifespan, and acceptable issuers and audiences. These settings influence which tokens are accepted by PureJWT during verification.

```javascript
const jwt = new PureJWT({
  algorithm: "HS384", // Default is HS256.
  secret: process.env.SECRET,
  acceptableIssuers: "your-awesome-server.com", // Can also be an array of strings
  acceptableAudiences: ["apiService", "userService"], // Can also be a string
  durationInMinutes: 7 * 24 * 60, // Token lifespan default is 24 hours
});
```

Create a JWT token:

```javascript
const payload = {
  sub: "1234567890", // 'Subject' - Traditionally it's the UserID
  email: "john.doe@your-awesome-server.com",
  role: "admin",
  exp: Date.now() + 1000 * 60 * 15, // Expiration 15 minutes
};
const token = jwt.createToken(payload);
```

Verify a JWT token:

```javascript
try {
  const payload = jwt.verifyToken(token);
  console.log(payload.sub);
} catch (PureJWTError) {
  console.error(PureJWTError);
}
```

For more detailed information on usage, please refer to the detailed API Reference section.

## Generating Keys

You can use PureJWT to generate public/private keys in PEM format. Generate these keys once in the development stage and store them as string values in your secure environment variables.

```javascript
// 'secp384r1' corresponds to ES384
// 'secp521r1' corresponds to ES512
const { privateKey, publicKey } = PureJWT.generatePublicPrivateKeys("ec", { 
  namedCurve: "prime256v1" // corresponds to ES256
});
console.log(`PRIVATE_KEY="${privateKey}"`);
console.log(`PUBLIC_KEY="${publicKey}"`);
```

You can also create RSA keys similarly.

```javascript
// A modulusLength of 3072 corresponds to RS384
// A modulusLength of 4096 corresponds to RS512
const { privateKey, publicKey } = PureJWT.generatePublicPrivateKeys("rsa", {
  modulusLength: 2048, // corresponds to RS256
});
```

## API Reference

- `PureJWT.generateSecret()`: Generates a secure secret for HMAC algorithms.
- `PureJWT.generatePublicPrivateKeys(algorithm, options)`: Generates private and public keys for RSA, RSA-PSS, and ECDSA algorithms.
- `PureJWT.extractJwtFromBearer(tokenWithPrefix)`: Extracts the JWT token from a bearer, basic, or digest authentication scheme.
- PureJWTError: Custom error class that includes a message and statusCode.

## Error handling

PureJWT introduces a custom error type, `PureJWT.PureJWTError`, for more precise error handling in your applications. It includes a message and statusCode:

```javascript
{
  statusCode: 401,
  message: 'Token signature is invalid',
  original_error: Error
}
```

## Example

Here's an example of PureJWT being used in an Express app:

```javascript
const express = require("express");
const cookieParser = require("cookie-parser");
require("dotenv").config(); // Install with npm install --save dotenv

const app = express();

const jwt = new PureJWT({ secret: process.env.SECRET });
const sevenWeeksInMs = 7 * 24 * 60 * 60 * 1000;

// Login route to create a token
app.post("/login", (req, res) => {
  // Perform authentication logic, validate credentials, etc.
  // Assuming successful authentication, create a token
  const exp = Date.now() + sevenWeeksInMs;
  const access_token = jwt.createToken({ sub: "your_user_id", exp });

  res.json({
    access_token,
    token_type: "Bearer",
    expires_in: exp,
  });
});

app.get("/api/orders", jwt.getTokenPayload("token"), async (req, res) => {
  try {
    const token = PureJWT.extractJwtFromBearer(req.headers.authorization);

    req.payload = jwt.verifyToken(token);

    const userID = req.payload.sub;

    // Fetch and verify user
    const user = await db.users.find(user => user.id === userID);

    if (user) {
      res.json({
        orderHistory: [
          /**...**/
        ],
      });
    } else {
      res.status(404).json({ message: "User not found." });
    }
  } catch (err) {
    return res.status(err.statusCode || 500).json({ message: err.message });
  }
});
```

## Contributing

Contributions are always welcome! Please review the Contributing guidelines.

## License

MIT License
