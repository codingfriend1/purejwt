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
- A custom error type, `PureJWT.PureJWTError`, for precise error handling.

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
const jwt = new PureJWT({
  secret: process.env.SECRET,
});
```

Generate and store private/public keys as secure environment variables. Use these keys to initialize PureJWT without needing to specify the algorithm (except for `PS256`, `PS384`, or `PS512`).

```javascript
const jwt = new PureJWT({
  privateKey: process.env.PRIVATE_KEY,
  publicKey: process.env.PUBLIC_KEY,
});
```

During initialization, you can specify options such as token lifespan, and acceptable issuers and audiences. These settings influence which tokens are accepted by PureJWT during verification.

```javascript
const jwt = new PureJWT({
  secret: process.env.SECRET,
  algorithm: "HS384", // Default algorithm is HS256.
  durationInMinutes: 7 * 24 * 60, // Default token lifespan is 24 hours
  acceptableIssuers: "securetoken.hostluxe.com", // Can also be an array of strings
  acceptableAudiences: [
    "microservice.hostluxe.com",
    "premiumservice.hostluxe.com",
  ], // Can also be a string
});
```

Create a JWT token:

```javascript
const payload = {
  sub: "1234567890", // 'Subject' - Traditionally it's the UserID
  role: "admin",
  exp: Date.now() + 1000 * 60 * 15, // Expiration 15 minutes
};
const token = jwt.createToken(payload);
```

Verify a JWT token:

```javascript
try {
  const payload = jwt.verifyToken(token);
} catch (PureJWTError) {
  res.status(PureJWTError.statusCode).json({ message: PureJWTError.message });
}
```

For more detailed information on usage, please refer to the detailed API Reference section.

## Key Creation

Use PureJWT to generate public/private keys in PEM format once during development. Store these keys as strings in your secure environment variables.

```javascript
const { privateKey, publicKey } = PureJWT.generatePublicPrivateKeys("ec", {
  namedCurve: "prime256v1",
});
console.log(`PRIVATE_KEY="${privateKey}"`);
console.log(`PUBLIC_KEY="${publicKey}"`);
```

## API Reference

- **PureJWT.generateSecret()**: Creates a secure secret for HMAC algorithms.
- **PureJWT.generatePublicPrivateKeys(algorithm, options)**: Produces private and public keys for RSA, RSA-PSS, and ECDSA algorithms.
  - With the **'rsa'** algorithm, **options.modulusLength** values of **2048**, **3072**, and **4096** match **256**, **384**, and **512** bit lengths respectively.
  - With the **'ec'** algorithm, **options.namedCurve** values of **'prime256v1'**, **'secp384r1'**, and **'secp521r1'** match **ES256**, **ES384**, and **ES512** respectively.
- **PureJWT.extractJwtFromBearer(tokenWithPrefix)**: Retrieves the JWT token from a bearer, basic, or digest authentication scheme.
- **PureJWTError**: A unique error class featuring a message and statusCode.

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

app.get("/api/orders", async (req, res) => {
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

## Disclaimer

This library, herein referred to as "this Software", is provided "as is", without any warranty of any kind, expressed or implied. The author(s) and maintainer(s) of this Software do not provide any guarantee as to its functionality, correctness, or suitability for any specific purpose.

Users of this Software are solely responsible for determining the appropriateness of its use, and assume all risks associated with its use, including but not limited to the risks of program errors, damage to or loss of data, programs or equipment, and unavailability or interruption of operations.

The author(s) and maintainer(s) of this Software will not be liable for any direct, indirect, consequential, incidental, special, punitive or other damages whatsoever, including without limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss, arising out of the use or inability to use this Software, even if advised of the possibility of such damages.

By using this Software, you acknowledge and agree to this disclaimer and assume full responsibility for all risk associated with the use of this Software.

## License

MIT License
