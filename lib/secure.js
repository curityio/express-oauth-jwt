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

const jose = require('jose');
const async = require('async');

const jwksService = require('./jwksService');

module.exports = function(settings, options) {
    const resolvedOptions = {
      scope: [],
      claims: [],
      ...options
    };

    return function(req, res, next) {
        // Check if Authorization header is present
        const authHeader = req.headers.authorization;
        if (!authHeader) {
            return res.status(401).json({ message: "Authorization header missing." }); 
        }

        // Authorization header should have the form "Bearer <token_value>"
        const token = authHeader.split(' ')[1];
        if (!token) {
            return res.status(401).json({ message: "Authorization header value is malformed." });
        }

        async.waterfall([
            function getKeyStore(callback) { // Obtain keyStore information from JWKS endpoint
                jwksService(settings.jwks_uri, callback);
            },
            function(keyStore, allowKeyRefresh, callback) { // Decode and verify the token
                verifyToken(token, keyStore, allowKeyRefresh, callback);
            },
            function verifyScopes(verifiedToken, callback) { // Verify whether token contains required scopes
                if (!tokenHasAllExpectedScopes(verifiedToken.scope, resolvedOptions.scope)) {
                    return callback(new Error("Token does not have all required scopes."));
                }
            
                callback(null, verifiedToken);
            },
            function verifyClaims(verifiedToken, callback) { // Verify whether token contains required claims and their values
                if (!tokenHasRequiredClaims(verifiedToken, resolvedOptions.claims)) {
                    return callback(new Error("Token is missing some required claims or claims does not have required values."));
                }
            
                callback(null, verifiedToken);
            }
        ], (error, verifiedToken) => {
            if (error) {
                return res.status(403).json({ message: error.message });
            }

            req.claims = verifiedToken;
            next();
        });
    }
}

function tokenHasAllExpectedScopes(scope, expectedScopes) {
    for (let index = 0; index < expectedScopes.length; index++) {
        if (!scope.includes(expectedScopes[index])) {
            return false;
        }
    }

    return true;
}

function tokenHasRequiredClaims(token, expectedClaims) {
    for (let index = 0; index < expectedClaims.length; index++) {
        const expectedClaim = expectedClaims[index];
        const claim = token[expectedClaim.name];

        if (claim === undefined || claim === null) {
            return false;
        }

        if (expectedClaim.value && claim != expectedClaim.value) {
            return false;
        }
    }

    return true;
}

function verifyToken(token, keyStore, allowKeyRefresh, callback) {
    let verifiedToken;
    try {
        verifiedToken = jose.JWT.verify(token, keyStore, {
            issuer: settings.issuer,
            audience: settings.audience
        });
    } catch (err) {
        if (err.code == 'ERR_JWKS_NO_MATCHING_KEY' && allowKeyRefresh) {
            // Try to fetch new keys from JWKS endpoint
            return verifyTokenWithRefreshedKey(token, callback)
        } else {
            return callback(err);
        }
    }

    callback(null, verifiedToken);
}

function verifyTokenWithRefreshedKey(token, cb) {
    async.waterfall([
        function getFreshKeyStore(callback) {
            jwksService(settings.jwks_uri, callback, true);
        },
        function(keyStore, allowKeyRefresh, callback) {
            verifyToken(token, keyStore, allowKeyRefresh, callback);
        }
    ], function(error, verifiedToken) {
        if (error) {
            return cb(error);
        }
        cb(null, verifiedToken);
    });
}
