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

 /**
 * Here lives the secured controller.
 */
const express = require('express');
const router = express.Router();
const secure = require('../lib/secure');
const settings = require('./settings');
const { getSimpleJwksService } = require('../lib/jwksService');

const jwksService = getSimpleJwksService(settings.jwks_uri);

// Here we mount the middleware which secures our endpoints with different options

// Require a valid JWT token to be present in the request 
router.get('/token', secure(jwksService), getSecuredWithAnyToken);

// Require a given scope to be present in the token
router.get('/scope', secure(jwksService, { scope: [ "read" ] }), getSecuredWithScope);

// Require claims in the token
const options = {
    claims: [
        { name: "sub" }, // Require the presence of a claim
        { name: "myClaim", value: "someRequiredValue" } // Require concrete value of a claim
    ]};
router.get('/claim', secure(jwksService, options), getSecuredWithClaims);

module.exports = router;

// Endpoints which return data.
function getSecuredWithAnyToken(req, res, next) {
    res.status(200).json({ data: "Some data from secured endpoint.", user: req.claims.sub });
}

function getSecuredWithScope(req, res, next) {
    res.status(200).json({ data: "Some data from secured endpoint.", user: req.claims.sub, scope: req.claims.scope });
}

function getSecuredWithClaims(req, res, next) {
    res.status(200).json({ data: "Some data from secured endpoint.", user: req.claims.sub, audience: req.claims.aud });
}
