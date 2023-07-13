# PureJWT
PureJWT is a lightweight, standalone library for JSON Web Token (JWT) creation, verification, and manipulation. Designed with ease-of-use and security in mind, it removes all reliance on third-party libraries, granting developers increased control and transparency over their web token operations. From generating public-private keys to verifying token signatures, PureJWT handles it all in a minimal, straightforward manner. It facilitates the use of both symmetric (HMAC) and asymmetric (RSA, RSA-PSS, ECDSA) cryptographic algorithms.

## Installation
To install PureJWT, use npm as shown below:

```bash
npm install --save purejwt
```

## Features
PureJWT supports the following algorithms

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

It also:

- Allows generation of a secret for HMAC algorithms.
- Generates public and private keys for RSA and ECDSA algorithms.
- Capable of encoding and decoding JWTs.
- Facilitates signing of JWTs.
- Verifies JWTs.

## Usage
To start using PureJWT, first import the class as follows:

```javascript
const PureJWT = require('purejwt')
```

### Creating a Secret
To create a secure secret, you can use the PureJWT.generateSecret() function.

```javascript
const secret = PureJWT.generateSecret()
console.log(`SECRET="${secret}"`)
```
Generate the secret once during development and store it as a secret environment variable for future use in your code. **Make sure `.env` is added to your `.gitignore`**. You don't want anyone to see your SECRET.

```env
#.env This is just an example so don't use this exact key
SECRET="49b13c5f1d476472e9a5e3cd7c25e5cb1d040ec652549e1972a789891b751da6"
```

By default, PureJWT will use `HS256` when you provide a secret, but you can override this by specifying the algorithm: `algorithm: 'HS384'` or `algorithm: 'HS512'`.

```javascript
const jwt = new PureJWT({ secret: process.env.SECRET })
```

### Using Private/Public Keys
PureJWT enables you to generate public/private keys, returning a PEM formatted string for use. Generate these keys once during development and store them as strings in your secret environment variables.

```javascript
const algorithm = 'ec'
const { privateKey, publicKey } = PureJWT.generatePublicPrivateKeys(algorithm, { 
  namedCurve: 'prime256v1' //ES256
  // namedCurve: 'secp384r1' //ES384
  // namedCurve: 'secp521r1' //ES512
})
console.log(`PRIVATE_KEY="${privateKey}"`)
console.log(`PUBLIC_KEY="${publicKey}"`)
```
RSA keys can also be generated similarly.
```javascript
const { privateKey, publicKey } = PureJWT.generatePublicPrivateKeys('rsa', { 
  modulusLength: 2048 // RS256
  // modulusLength: 3072 // RS384
  // modulusLength: 4096 // RS512
})
console.log(`PRIVATE_KEY="${privateKey}"`)
console.log(`PUBLIC_KEY="${publicKey}"`)
```
Store the contents of privateKey and publicKey in a private .env file (added to `.gitignore`).

```makefile
# .env
# Example Keys, don't actually use these

PRIVATE_KEY="-----BEGIN PRIVATE KEY-----
MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgpf+lgdYq4kwY9bO2QFO6
knxl7brXmVsyqknUf04YhkehRANCAAQPciMXPXea4aJT0yRRoYVzQu+LFsqCtuEu
HDZGJWXHyxrSk96oyXK0k5cekXtYFLt6KPGJSPX/2/E1uJ1bZYca
-----END PRIVATE KEY-----"

PUBLIC_KEY="-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAED3IjFz13muGiU9MkUaGFc0LvixbKgrbh
Lhw2RiVlx8sa0pPeqMlytJOXHpF7WBS7eijxiUj1/9vxNbidW2WHGg==
-----END PUBLIC KEY-----"
```
PureJWT is equipped to automatically detect the suitable algorithm based on the provided keys. There's no need to specify the algorithm. However, PureJWT cannot automatically detect `PS256`, `PS384`, `PS512` algorithms as these must be explicitely specified.

```javascript
require('dotenv').config(); // Install with npm install --save dotenv

const jwt = new PureJWT({
  //algorithm: 'PS256',
  privateKey: process.env.PRIVATE_KEY, 
  publicKey: process.env.PUBLIC_KEY 
})
```

### Additional Options
Additional information can be provided when creating your instance. In the following example, the token will automatically expire after one week (7 days * 24 hours * 60 minutes). The default expiration is 1 day. The list of accepted issuers and audiences can also be set as an array of strings or a single string that will enforce what token audiences and issuers PureJWT accepts during verification.

```javascript
const jwt = new PureJWT({ 
  algorithm: 'HS384', 
  secret: process.env.SECRET, 
  acceptableIssuers: 'your-awesome-server.com', // Can also be an array of strings
  acceptableAudiences: ['apiService', 'userService'], // Can also be a single string
  durationInMinutes: 7 * 24 * 60 
})
```

## Creating a JWT Token
You can incorporate any information you want in the payload. Conventionally, the UserID is stored under `sub`, which stands for subject. PureJWT will refuse tokens where the `aud` and `iss` don't match the `acceptableAudiences` and `acceptableIssuers` set in instantiation. If you provide an `iat` (Issued At), `exp` (Expiration), `nbf` (Not Before), PureJWT will enforce those timestamps. For `iat`, PureJWT will calculate the expiration by adding the provided `iat` to the `durationInMinutes` supplied during instantiation. `durationInMinutes` defaults to 24 hours if not explicitely set. Traditionally, `iat`, `exp`, and `nbf` are set in seconds, but if you set them in milliseconds, PureJWT will detect that and convert it accordingly.

```javascript
const payload = { 
  sub: '1234567890', 
  email: 'john.doe@your-awesome-server.com', 
  role: 'admin',
  exp: Date.now() + (1000 * 60 * 15) // 15 minutes
}
const token = jwt.createToken(payload)
console.log(token) 
//token === "ekeyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaXNzIjoibXlhcHAiLCJpYXQiOjE2ODkxMzI4NTB9.tGwQ/oedECLkQoGmUAlGyMr8vlzsJ27EqYNe3QthDpLB5eUBKk6nEZt4WTdQqB8hGt/j5IhrkUEkCMhQlcKOXg=="
```

## Verifying a JWT Token
To verify a JWT token, use the following approach:

```javascript
try {
  const payload = jwt.verifyToken(token)
  console.log(payload.sub)
} catch(PureJWTError) {
  console.error(PureJWTError)
}
```

## Extract Token from Bearer
PureJWT can also extract the token from a string beginning with Bearer, Basic, or Digest with `PureJWT.extractJwtFromBearer(tokenWithPrefix)`.

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
Here is an example of how you can use the PureJWT in an Express app:

```javascript
const express = require('express');
const cookieParser = require('cookie-parser');
require('dotenv').config(); // Install with npm install --save dotenv

const app = express();

const jwt = new PureJWT({ secret: process.env.SECRET });
const sevenWeeksInMs = 7 * 24 * 60 * 60 * 1000

// Login route to create a token
app.post('/login', (req, res) => {
  // Perform authentication logic, validate credentials, etc.
  // Assuming successful authentication, create a token
  const exp = Date.now() + sevenWeeksInMs;
  const access_token = jwt.createToken({ sub: 'your_user_id', exp });

  res.json({
    access_token, 
    token_type: "Bearer", 
    expires_in: exp 
  });
});

app.get('/api/orders', jwt.getTokenPayload('token'), async (req, res) => {
  try {
    const token = PureJWT.extractJwtFromBearer(req.headers.authorization);
    req.payload = jwt.verifyToken(token);

    const userID = req.payload.sub;

    // Fetch and verify user
    const user = await db.users.find(user => user.id === userID);

    if(user) {
      res.json({ orderHistory: [/**...**/] });
    } else {
      res.status(404).json({ message: 'User not found.' });
    }

  } catch(err) {
    return res.status(err.statusCode || 500).json({ message: err.message });
  }
});
```

## Contributing
We encourage you to contribute to PureJWT! Please check out the Contributing guidelines.

## License
MIT License