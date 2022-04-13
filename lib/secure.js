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

const { jwtVerify } = require('jose');
const { InsufficientScopeError, TokenClaimsError } = require('./errors');

module.exports = function(getKey, options) {
    const resolvedOptions = {
      scope: [],
      claims: [],
      realm: '',
      ...options
    };

    const wwwAuthenticate = 'WWW-Authenticate';
    const wwwAuthValue = resolvedOptions.realm !== '' ? 'Bearer realm="' + resolvedOptions.realm + '"' : 'Bearer';

    return async function(req, res, next) {
        // Check if Authorization header is present
        const authHeader = req.headers.authorization;
        if (!authHeader) {
            return res.status(401).append(wwwAuthenticate, wwwAuthValue).send(); 
        }

        // Authorization header should have the form "Bearer <token_value>"
        const headerParts = authHeader.split(' ');

        if (headerParts.length !== 2 || headerParts[0] !== 'Bearer') {
            return res.status(401).append(wwwAuthenticate, wwwAuthValue).send();
        }

        const token = headerParts[1];

        if (!token) {
            return sendErrorResponse(res, 'invalid_token', 'Bearer token is empty');
        }

        return jwtVerify(token, getKey)
            .then((verifiedToken) => {
                if (!tokenHasAllExpectedScopes(verifiedToken.payload.scope, resolvedOptions.scope)) {
                    throw new InsufficientScopeError()
                }

                if (!tokenHasRequiredClaims(verifiedToken.payload, resolvedOptions.claims)) {
                    throw new TokenClaimsError()
                }

                return verifiedToken
            })
            .then((verifiedToken) => {
                req.claims = verifiedToken.payload;
                next();
            })
            .catch(error => {
                if (error instanceof InsufficientScopeError) {
                    return sendErrorResponse(res, 'insufficient_scope', error.message);
                }

                return sendErrorResponse(res, 'invalid_token', error.message.replace(/"/g, "'"));
            });
    }

    function tokenHasAllExpectedScopes(scope, expectedScopes) {
        if (!expectedScopes.length) {
            return true;
        }

        if (!scope || !scope.length) {
            return false;
        }

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

            if (expectedClaim.value && claim !== expectedClaim.value) {
                return false;
            }
        }

        return true;
    }

    function sendErrorResponse(res, error, description) {
        return res
            .status(403)
            .append(wwwAuthenticate, wwwAuthValue)
            .append(wwwAuthenticate, 'error="' + error + '"')
            .append(wwwAuthenticate, 'error_description="' + description + '"')
            .send();
    }
}
