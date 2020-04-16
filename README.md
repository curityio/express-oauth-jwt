# Securing endpoints in Express with OAuth tokens

This example code shows a simple way of creating a middleware which secures endpoints in Express with JWT tokens. The
implementation uses a JWKS endpoint to get a key required for verification of token signature.

## Running the example

1. Download the code and install dependencies running `npm i`.
2. Rename the file `config-template.js` in the `src` directory to `config.js` and fill with proper settings (see below).
3. Start the demo server with `npm start`.
4. The server exposes endpoints `/secured/token`, `/secured/scope` and `/secured/claim` which present different options
of securing the endpoints.

## Settings

To properly verify incoming signed JWT tokens you need to fill the settings:

1. The `issuer` should be set to the identifier of the issuer of tokens you will accept.
2. The `audience` should be the accepted value of the `audience` claim.
3. `jwks_uri` should be the JWKS endpoint exposed by the Authorization Server.

An example of a prepared settings file:

```js
{
    issuer: "https://my-oauth-server.com/oauth/my-oauth",
    audience: "some-client-id",
    jwks_uri: "https://my-oauth-server.com/oauth/my-oauth/jwks"
}
```

## Usage

You can find the middleware securing the endpoints in the `src/secure.js` file. It uses the `jose` node library to
decode and verify the JWT token. The middleware also shows how you can easily add additional verification of the
received tokens, by checking scopes and claims of the token. Finally the claims of the received tokens are added to the
request objects in a `claims` field.

### Authorizing the request based on scopes

In order to limit the request to given scopes pass the middleware an `options` object with a list of strings in the
`scope` field:

```js
const secure = require('../src/secure');
router.use(secure({ scope: ["scope1", "scope2"] }));
```

### Authorizing the request based on claims

In order to limit the request based on claims pass the middleware an `options` object with a list of claims in the
`claims` field. Each claim should be an object with the `name` field. Additionally you can also set the `value` field. If
only the `name` field is set then the validator only checks wether the claim exists in the token. If `value` is set as
well, then the value of the claim in the token must also match.

```js
const secure = require('../src/secure');
router.use(secure({ claims: [ { name: "someClaim", value: "withValue" } ] }));
```

### JWKS support

The `jwksService` class reads the key store data from a JWKS endpoint exposed by the Authorization Server and stores this
information in memory. Usually the key store data does not change dynamically, but still it can change over time. Thus,
the `secure` middleware tries to refresh the key store data if no suitable key is found to verify the token.

## Using Opaque tokens

The middleware shown here uses JWT tokens, which can be easily decoded offline into a JSON object containing claims about
the user sending the request. But it is not always the case that JWT tokens are used for authorization. Sometimes the
Authorization Server will issue an opaque token, which is just an identifier of the user's data, and the data itself is
kept safely with the Authorization Server.

If you use opaque tokens for authorization then the token needs to be exchanged for data associated with it. It
cannot be decoded as the value of the token does not contain any data. In such situation the best approach is to use the
Phantom token approach - let your API gateway exchange the opaque token for a JWT. This way your service will always
receive a JWT which can be decoded with the approach shown here.

You can find out more on the Phantom token approach in the 
(Phantom Token Pattern)[https://curity.io/resources/architect/api-security/phantom-token-pattern/] article. If you
want to learn how to enable Phantom tokens in Curity take a look at 
(this tutorial)[https://curity.io/resources/operate/tutorials/integration/introspect-with-phantom-token/].

## Access token claims in Request object

The `secure` middleware adds claims obtained from the access token into the Express' request object, in the `claims`
field. You can access these claims in any other middleware which is next in chain, or in the controllers.

```js
function getLibraryData(req, res, next) {
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
