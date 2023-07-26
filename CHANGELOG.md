# Changelog

## Version 2.0.2
Released 2023-07-26

- Authorizing the request based on claim values now properly handles array claims. The request is authorized if the required value is one of the elements of the array.

## Version 2.0.1
Released 2022-10-07

- Updated jose library to 4.10.0

## Version 2.0.0
Released: 2022-04-13

- Updated jose library to version 4.
- Removed `jwksService` class, as the functionality of downloading keys from a JWKS endpoint is now provided by jose directly.
- The `secure` middleware now needs a `getKey` function, not a `jwksService` as a constructor parameter.

## Version 1.1.0
Released: 2021-04-02

## Version 1.0.1
Released: 2020-04-29

## Version 1.0.0
Released: 2020-04-29

Initial version of the library.
