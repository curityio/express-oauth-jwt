# Securing endpoints in Express with OAuth JWT tokens
       
[![Quality](https://img.shields.io/badge/quality-test-yellow)](https://curity.io/resources/code-examples/status/)
[![Availability](https://img.shields.io/badge/availability-source-blue)](https://curity.io/resources/code-examples/status/)


This library allows you to secure your Express endpoints with JWTs. The implementation uses a JWKS endpoint of an
Authorization Server to get keys required for the verification of the token signature.

## Running the example

1. Download the code and install dependencies running `npm i`.
2. In `settings.js` in the `example` directory set the URI of the JWKS endpoint exposed by the Authorization Server.
3. Start the demo server with `npm run example`.
4. The server exposes endpoints `/secured/token`, `/secured/scope` and `/secured/claim` which present different options
of securing the endpoints.

## Installing the dependency

Use `npm` to install the library in your project:

```bash
npm install express-oauth-jwt
```

## Usage

### Preparing the JWKS Service

The `secure` middleware needs a JWKS Service which is capable of retrieving any keys needed to verify the signature of
the incoming token. To instantiate the service use the convenience method `getSimpleJwksService`, providing it with the
JWKS endpoint URI.

```javascript
const { getSimpleJwksService } = require('express-oauth-jwt');

const jwksService = getSimpleJwksService("https://myoauthserver.com/auth/jwks");
```

The service will cache the obtained JWKS data in memory. If a key is encountered, which is not present in the cache the
service will try to get new JWKS data from the endpoint. The request will fail only when the key is not found in the
refreshed key store.

If you need more control over the service you can create it yourself providing it with:

- a cache implementation
- an https client
- the JWKS endpoint URI

```javascript
const { jwksService } = require('express-oauth-jwt');
const jwksServiceInstance = jwksService(cache, jwksUri, client);
```

#### The cache

The cache needs to be an object which exposes two asynchronous methods:

- `getKeyStore(): Promise<jose.JWKS.Keystore>`
- `setKeyStore(keystore): Promise` - `keystore` is of type `jose.JWKS.Keystore`

The default implementation keeps the value in memory.

#### The https client

This is the node native `https` client. Pass your instance of the client if you need to set any options.

### Securing an endpoint

To secure an endpoint apply the `secure` middleware to it. Any endpoint with this middleware applied will require a valid
JWT token sent in the `Authorization` header in the form `Bearer <token_value>`. The token, if valid, will be decoded
and all its' claims will be set in the request in a `claims` field.

If the token does not pass validation, a 403 response will be returned. If no JWT token is found in the request, a 401
response will be returned. The response will have the `WWW-Authenticate` header set with detailed information on
the error (as specified in the [RFC 6750: The OAuth 2.0 Authorization Framework: Bearer Token Usage](https://tools.ietf.org/html/rfc6750)).

If you want the `WWW-Authenticate` to return a `realm` value, pass the middleware an `options` objects with the `realm`
option set.

```javascript
const { secure } = require('express-oauth-jwt');
router.use(secure(jwksService, { realm: 'my-realm' }));
```

The `WWW-Authenticate` header in the error response will then might look like this:

```curl
WWW-Authenticate: Bearer realm="my-realm", error="invalid_token", error_description="..."
```

### Authorizing the request based on scopes

In order to limit the request to given scope values pass the middleware an `options` object with a list of strings in the
`scope` field:

```javascript
const secure = require('express-oauth-jwt');
router.use(secure(jwksService, { scope: ["scope1", "scope2"] }));
```

### Authorizing the request based on claims

In order to limit the request based on the presence or value of concrete claims, pass the middleware an `options` object
with a list of claims in the `claims` field. Each claim should be an object with at least the `name` field. Optionally
you can set the `value` field. If only the `name` field is set then the validator checks whether the claim
exists in the token. If `value` is set as well, then the value of the claim in the token must also match.

```javascript
const secure = require('express-oauth-jwt');
router.use(secure(jwksService, { claims: [ { name: "someClaim", value: "withValue" } ] }));
```

## Using Opaque tokens

This middleware uses JSON Web Tokens, which can be easily decoded offline into a JSON object containing claims about
the user or client sending the request. But this is not always the case that JWT tokens are used for authorization.
Sometimes the Authorization Server will issue an opaque token, which is just an identifier of the user's data, and the
data itself is kept safely with the Authorization Server.

If you use opaque tokens for authorization then the token needs to be exchanged for data associated with it. It
cannot be decoded, as the value of the token does not contain any data. In such situation, the best approach is to use the
Phantom token approach - let your API gateway exchange the opaque token for a JWT. This way your service will always
receive a JWT which can be decoded with the approach shown here.

You can find out more on the Phantom token approach in the
[Phantom Token Pattern](https://curity.io/resources/architect/api-security/phantom-token-pattern/) article.

If you're using Curity Identity Server you can learn how to enable Phantom tokens with the help of
[this tutorial](https://curity.io/resources/operate/tutorials/integration/introspect-with-phantom-token/).

## Access token claims in Request object

The `secure` middleware adds claims obtained from the access token into the Express request object, in the `claims`
field. You can access these claims in any other middleware which is next in chain and in the controllers.

```javascript
function getLibraryData(req, res) {
    if (req.claims.myClaim == 'someValue') {
        ...
    }
    ...
}
```

## Questions and Support

For questions and support, contact Curity AB:

> Curity AB
>
> info@curity.io
> https://curity.io

Copyright (C) 2020 Curity AB.
