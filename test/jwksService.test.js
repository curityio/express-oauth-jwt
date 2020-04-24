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

const jwksService = require('../lib/jwksService');
const InMemoryCache = require('../lib/InMemoryCache');

const keystore = [{
    kid: "1234"
}];

const clientMock = (cache) => {
    const request = {};
    request.on = sinon.stub();

    const client = {};
    client.get = sinon.stub().callsFake(() => {
        cache.setKeyStore(keystore);
        return request;
    });

    return client;
};

test('Should keep keyStore result in cache', async t => {
    const cache = new InMemoryCache();
    const client = clientMock(cache);

    const jwksServiceInstance = jwksService(cache, "http://localhost", client);

    await jwksServiceInstance(() => {}, false);
    await jwksServiceInstance(() => {}, false);
    await jwksServiceInstance(() => {}, false);

    t.is(client.get.callCount, 1, 'KeyStore should be fetched from remote only once');
    t.is(await cache.getKeyStore(), keystore, 'KeyStore should be saved in cache');
});

test('Should refresh cache when asked', async t => {
    const cache = new InMemoryCache();
    const client = clientMock(cache);

    const jwksServiceInstance = jwksService(cache, "http://localhost", client);

    await jwksServiceInstance(() => {}, false);
    await jwksServiceInstance(() => {}, true);
    await jwksServiceInstance(() => {}, true);

    t.is(client.get.callCount, 3, 'KeyStore should be fetched from remote three times.');
});
