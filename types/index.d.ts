import { RequestHandler } from "express";
import * as https from 'https';
import { JWKS } from "jose";
import KeyStore = JWKS.KeyStore;


declare namespace errors {
    class InsufficientScopeError extends Error {
        constructor();
    }
    class TokenClaimsError extends Error {
        constructor();
    }
}

interface Claim {
    name: string;
    value?: string;
}

interface Options {
    claims?: Claim[];
    scope?: string[];
}

interface JwksService {
    (callback: (error?: Error, keyStore?: KeyStore) => void, refreshKeyStore?: boolean): Promise<void>;
}

interface Cache {
    getKeyStore(): Promise<KeyStore>;
    setKeyStore(keystore: KeyStore): Promise<void>;
}

declare class InMemoryCache implements Cache {
    keyStore: KeyStore;
    getKeyStore: () => Promise<KeyStore>;
    setKeyStore: (keyStore: KeyStore) => Promise<void>;
}

declare function jwksService(cache: Cache, jwksUri: string, client?: typeof https): JwksService;
declare function getSimpleJwksService(jwksUri: string): JwksService;
declare function secure(jwksService: JwksService, options?: Options): RequestHandler;
export { secure, jwksService, getSimpleJwksService, InMemoryCache, errors };
export {Claim, Options, JwksService, Cache};
