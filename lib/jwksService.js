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

const jwksService = (cache, jwksUri, client = null) => {
    if (!client) {
        client = require('https');
    }

    return (callback, refreshKeyStore = false) => Promise.resolve()
        .then(() => {
            if (!refreshKeyStore) {
                return cache.getKeyStore();
            }

            return null;
        })
        .then((keyStore) => {
            if (keyStore !== null) {
                return callback(null, keyStore);
            }

            return client.get(jwksUri, (response) => {
                if (response.statusCode < 200 || response.statusCode >= 400) {
                    return callback(new Error("JWKS endpoint responded with " + response.statusCode + " status code."));
                }

                let data = '';

                // A chunk of data has been received.
                response.on('data', (chunk) => {
                    data += chunk;
                });

                // The whole response has been received. Print out the result.
                response.on('end', () => {
                    const keyStore = createKeyStore(data);
                    cache.setKeyStore(keyStore)
                        .then(() => {
                            callback(null, keyStore);
                        });
                });
            }).on("error", (error) => {
                callback(error);
            });
        });

    function createKeyStore(jwksData) {
        return jose.JWKS.asKeyStore(JSON.parse(jwksData));
    }
}

const getSimpleJwksService = (jwksUri) => {
    const InMemoryCache = require('./InMemoryCache');
    const cache = new InMemoryCache();

    return jwksService(cache, jwksUri);
};

exports = module.exports = jwksService;
exports.jwksService = jwksService;
exports.getSimpleJwksService = getSimpleJwksService;
