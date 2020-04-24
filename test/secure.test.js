/*
 *  Copyright 2020 Curity AB
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

const test = require('ava');
const sinon = require('sinon');
const secureMiddleware = require('../lib/secure');
const { JWK: { asKey, generateSync }, JWKS: { asKeyStore }, JWT } = require('jose');

const requestMock = (authorizationHeaderValue) => {
    const req = {};
    req.headers = {};
    
    if (authorizationHeaderValue) {
        req.headers.authorization = authorizationHeaderValue;
    }

    return req;
};

const responseMock = () => {
    const res = {};
    res.status = sinon.stub().returns(res);
    res.json = sinon.stub().returns(res);
    res.append = sinon.stub().returns(res);
    res.send = sinon.spy();
    return res;
};

const wwwAuthenticate = 'WWW-Authenticate';

const rsaKey = generateSync('RSA');
const { d, e, n } = rsaKey.toJWK(true);
const keyStore = asKeyStore({ keys: [{ kty: 'RSA', d, e, n }] }, { calculateMissingRSAPrimes: true });



const jwkServiceMock = (cb) => {
    cb(null, keyStore);
}

const getJwt = (scope, additionalClaims) => {
    const payload = {
        "iss": "test",
        "sub": "someUser",
        ...additionalClaims
    };

    if (scope) {
        payload.scope = scope;
    }

    return JWT.sign(payload, keyStore.get({kty: 'RSA'}));
}

test('should return 401 with WWW-Autenticate header when request does not contain Authorization header', t => {
    const req = requestMock();
    const res = responseMock();

    const secure = secureMiddleware();

    secure(req, res, () => {});

    t.true(res.status.calledWith(401), 'Response status is not 401');
    t.true(res.append.calledWith('WWW-Authenticate', 'Bearer'), 'Response header WWW-Authenticate has wrong value.');
    t.true(res.send.called, 'send() should be called on response object.');
});

test('should respond with proper realm value when missing Authorization header', t => {
    const req = requestMock();
    const res = responseMock();

    const secure = secureMiddleware(jwkServiceMock, { realm: "demo-app" });

    secure(req, res, () => {});

    t.true(res.status.calledWith(401), 'Response status is not 401');
    t.true(res.append.calledWith('WWW-Authenticate', 'Bearer realm="demo-app"'), 'Response header WWW-Authenticate has wrong value.');
    t.true(res.send.called, 'send() should be called on response object.');
});

test('should return 401 with WWW-Autenticate header when Authorization header is malformed', t => {
    const authorizationHeader = "Bearer";
    const req = requestMock(authorizationHeader);
    const res = responseMock();

    const secure = secureMiddleware();

    secure(req, res, () => {});

    t.true(res.status.calledWith(401), 'Response status is not 401');
    t.true(res.append.calledWith('WWW-Authenticate', 'Bearer'), 'Response header WWW-Authenticate has wrong value.');
    t.true(res.send.called, 'send() should be called on response object.');
});

test('should return 401 with WWW-Autenticate header when Authorization header not with Bearer', t => {
    const authorizationHeader = "Basic dXNlcjpwYXNzd29yZA==";
    const req = requestMock(authorizationHeader);
    const res = responseMock();

    const secure = secureMiddleware();

    secure(req, res, () => {});

    t.true(res.status.calledWith(401), 'Response status is not 401');
    t.true(res.append.calledWith('WWW-Authenticate', 'Bearer'), 'Response header WWW-Authenticate has wrong value.');
    t.true(res.send.called, 'send() should be called on response object.');
});

test('should return 403 with invalid_token error when token is empty', t => {
    const authorizationHeader = "Bearer ";
    const req = requestMock(authorizationHeader);
    const res = responseMock();

    const secure = secureMiddleware();

    secure(req, res, () => {});

    t.true(res.status.calledWith(403), 'Response status is not 403');
    t.true(res.append.calledWith(wwwAuthenticate, 'Bearer'), 'Response header WWW-Authenticate has wrong value.');
    t.true(res.append.calledWith(wwwAuthenticate, 'error="invalid_token"'), 'Response header WWW-Authenticate has wrong value.');
    t.true(res.append.calledWith(wwwAuthenticate, 'error_description="Bearer token is empty"'), 'Response header WWW-Authenticate has wrong value.');
    t.true(res.send.called, 'send() should be called on response object.');
});

test('should set token claims in request and call next() when valid token passed', t => {
    const authorizationHeader = "Bearer " + getJwt();
    const req = requestMock(authorizationHeader);
    const res = responseMock();
    const next = sinon.spy();

    const secure = secureMiddleware(jwkServiceMock, {});

    secure(req, res, next);

    t.truthy(req.claims, 'Token claims not present in the request');
    
    const expectedClaims = { "iss": "test", "sub": "someUser" };

    for (let [key, value] of Object.entries(expectedClaims)) {
        t.is(req.claims[key], value, 'Claim ' + key + ' should have value ' + value + ' but has: ' + req.claims[key]);
    }

    t.true(next.called, 'next() should be eventually called in the middleware.');
});

test('should return 403 with insufficient_scope when scope missing in token', t => {
    const authorizationHeader = "Bearer " + getJwt();
    const req = requestMock(authorizationHeader);
    const res = responseMock();
    const next = sinon.spy();

    const secure = secureMiddleware(jwkServiceMock, { scope: ['openid'] });

    secure(req, res, next);

    t.true(res.status.calledWith(403), 'Response status is not 403');
    t.true(res.append.calledWith(wwwAuthenticate, 'Bearer'), 'Response header WWW-Authenticate has wrong value.');
    t.true(res.append.calledWith(wwwAuthenticate, 'error="insufficient_scope"'), 'Response header WWW-Authenticate has wrong value.');
    t.true(res.append.calledWith(wwwAuthenticate, 'error_description="Token is missing some reuquired scope values"'), 'Response header WWW-Authenticate has wrong value.');
    t.true(res.send.called, 'send() should be called on response object.');
});

test('should call next() when required scope present in token', t => {
    const authorizationHeader = "Bearer " + getJwt('openid profile');
    const req = requestMock(authorizationHeader);
    const res = responseMock();
    const next = sinon.spy();

    const secure = secureMiddleware(jwkServiceMock, { scope: ['openid', 'profile'] });

    secure(req, res, next);

    t.true(next.called, 'next() should be eventually called in the middleware.');
});

test('should return 403 with invalid_token when claim missing in token', t => {
    const authorizationHeader = "Bearer " + getJwt();
    const req = requestMock(authorizationHeader);
    const res = responseMock();
    const next = sinon.spy();

    const secure = secureMiddleware(jwkServiceMock, { claims: [{ name: 'customClaim' }] });

    secure(req, res, next);

    t.true(res.status.calledWith(403), 'Response status is not 403');
    t.true(res.append.calledWith(wwwAuthenticate, 'Bearer'), 'Response header WWW-Authenticate has wrong value.');
    t.true(res.append.calledWith(wwwAuthenticate, 'error="invalid_token"'), 'Response header WWW-Authenticate has wrong value.');
    t.true(res.append.calledWith(wwwAuthenticate, 'error_description="Token is missing some required claims"'), 'Response header WWW-Authenticate has wrong value.');
    t.true(res.send.called, 'send() should be called on response object.');
});

test('should return 403 with invalid_token when claim has wrong value', t => {
    const authorizationHeader = "Bearer " + getJwt('', { customClaim: "WrongValue" });
    const req = requestMock(authorizationHeader);
    const res = responseMock();
    const next = sinon.spy();

    const secure = secureMiddleware(jwkServiceMock, { claims: [{ name: 'customClaim', value: 'CorrectValue' }] });

    secure(req, res, next);

    t.true(res.status.calledWith(403), 'Response status is not 403');
    t.true(res.append.calledWith(wwwAuthenticate, 'Bearer'), 'Response header WWW-Authenticate has wrong value.');
    t.true(res.append.calledWith(wwwAuthenticate, 'error="invalid_token"'), 'Response header WWW-Authenticate has wrong value.');
    t.true(res.append.calledWith(wwwAuthenticate, 'error_description="Token is missing some required claims"'), 'Response header WWW-Authenticate has wrong value.');
    t.true(res.send.called, 'send() should be called on response object.');
});

test('should call next() when required claims present in token', t => {
    const authorizationHeader = "Bearer " + getJwt('', { customClaim: 'AnyValue' });
    const req = requestMock(authorizationHeader);
    const res = responseMock();
    const next = sinon.spy();

    const secure = secureMiddleware(jwkServiceMock, { claims: [{ name: 'customClaim' }] });

    secure(req, res, next);

    t.true(next.called, 'next() should be eventually called in the middleware.');
});

test('should call next() when required claim has correct value', t => {
    const authorizationHeader = "Bearer " + getJwt('', { customClaim: 'CorrectValue' });
    const req = requestMock(authorizationHeader);
    const res = responseMock();
    const next = sinon.spy();

    const secure = secureMiddleware(jwkServiceMock, { claims: [{ name: 'customClaim', value: 'CorrectValue' }] });

    secure(req, res, next);

    t.true(next.called, 'next() should be eventually called in the middleware.');
});

test('should call next() when required claims present and have correct values and token has required scope', t => {
    const authorizationHeader = "Bearer " + getJwt('openid profile', { customClaim: 'CorrectValue', presentClaim: 'present' });
    const req = requestMock(authorizationHeader);
    const res = responseMock();
    const next = sinon.spy();

    const secure = secureMiddleware(jwkServiceMock, { scope: ['openid', 'profile'], claims: [{ name: 'presentClaim' }, { name: 'customClaim', value: 'CorrectValue' }] });

    secure(req, res, next);

    t.true(next.called, 'next() should be eventually called in the middleware.');
});

test('should return 403 with invalid_token when signature not valid', t => {
    const jwt = getJwt()
    const tamperedJwt = jwt.substring(0, jwt.length -10);
    const authorizationHeader = "Bearer " + tamperedJwt;
    const req = requestMock(authorizationHeader);
    const res = responseMock();
    const next = sinon.spy();

    const secure = secureMiddleware(jwkServiceMock, {});

    secure(req, res, next);

    t.true(res.status.calledWith(403), 'Response status is not 403');
    t.true(res.append.calledWith(wwwAuthenticate, 'Bearer'), 'Response header WWW-Authenticate has wrong value.');
    t.true(res.append.calledWith(wwwAuthenticate, 'error="invalid_token"'), 'Response header WWW-Authenticate has wrong value.');
    t.true(res.append.calledWith(wwwAuthenticate, 'error_description="signature verification failed"'), 'Response header WWW-Authenticate has wrong value.');
    t.true(res.send.called, 'send() should be called on response object.');
});

test('should refresh jwksStore when no key found', t => {
    const authorizationHeader = "Bearer " + getJwt();
    const req = requestMock(authorizationHeader);
    const res = responseMock();
    const next = sinon.spy();

    const oldRsaKey = generateSync('RSA');
    const oldKey = oldRsaKey.toJWK(true);
    const oldKeyStore = asKeyStore({ keys: [{ kty: 'RSA', d: oldKey.d, e: oldKey.e, n: oldKey.n }] }, { calculateMissingRSAPrimes: true });
    const jwksServiceMock = sinon.stub()
        .onFirstCall()
        .yields(null, oldKeyStore)
        .onSecondCall()
        .yields(null, keyStore);

    const secure = secureMiddleware(jwksServiceMock, {});

    secure(req, res, next);

    t.is(jwksServiceMock.callCount, 2, 'jwksService should be called twice');
    t.true(next.called, 'next() should be eventually called in the middleware.');
});
