import { RequestHandler } from "express";
import https from 'https';
import jose from 'jose';

declare namespace errors {
    declare class InsufficientScopeError extends Error {
        constructor();
    }
    declare class TokenClaimsError extends Error {
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
    (callback: any, refreshKeyStore?: boolean):any
}

interface Cache {
    getKeyStore(): Promise<jose.JWKS.KeyStore>;
    setKeyStore(keystore: jose.JWKS.KeyStore): Promise<jose.JWKS.KeyStore>;
}

declare class InMemoryCache implements Cache {
    keyStore: jose.JWKS.KeyStore;
    getKeyStore: () => Promise<jose.JWKS.KeyStore>;
    setKeyStore: (keyStore: jose.JWKS.KeyStore) => Promise<jose.JWKS.KeyStore>;
}

declare function jwksService(cache: Cache, jwksUri: string, client?: typeof https): JwksService;
declare function getSimpleJwksService(jwksUri: string): JwksService;
declare function secure(jwksService: JwksService, options?: Options): RequestHandler;
export { secure, jwksService, getSimpleJwksService, InMemoryCache, errors };
export {Claim, Options, JwksService, Cache};
