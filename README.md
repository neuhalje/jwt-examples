Encrypted and signed JWT
=================================

This example shows how a JWT can be signed and encrypted by a common shared key.

Goal
----------------------
- (**REQ.1**) Integrity protect a JWT
- (**REQ.2**) Protect confidentiality of the JWT
- (**REQ.3**) Allow the same secret (shared) key to be used for both

Drawbacks
----------------------
- Integrity protection is done twice: AES-GCM and HMAC. That makes the tokens quite long.

Structure
----------------------

The overall structure looks like this: A signed (**REQ.1**) JWT is encrypted (**REQ.2**) as JWE.

``` text
   ┌────────────────────────────────────┐
   │                                    │
   │ ┌────────────────────────────────┐ │
   │ │ { "iss": ....                  │ │
   │ │ ...                            │ │
   │ │ }                              │ │
   │ │                                │ │
   │ │JWT signed with HMAC and K2     │ │
   │ └────────────────────────────────┘ │
   │                                    │
   │ JWE encrypted with AES-GCM and K1  │
   └────────────────────────────────────┘
```

### Why two integrity protections?
There are two answers to it
- To have a good example on how to work with two keys derived from a common secret
- At times a business process is broken into IT in multiple steps. While the token is in the "outside" world, it needs confidentiality _and_ integrity. Once the token has been ingested only _integrity_ is needed. The double wrap allows just this: stripe the `JWE` layer once the token enters the internal zone. Encryption should _always_ include integrity protection, that is why we use  the `GCM` mode of AES.



Keys
------
The `HMAC` signature and the `AES-GCM` encryption should not use the same key, as it is a bad practice to directly use the same key for different operations.

In order to support a single shared key as source (**REQ.3**), the keys for JWT signing (`K2`) and the key for JWE encryption (`K1`) are derived from the `shared secret`:

`K1 := HKDF(key :=shared_secret, data := "K.1")` and `K2 := HKDF(key :=shared_secret, data := "K.2")`.

