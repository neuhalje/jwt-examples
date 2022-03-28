Encrypted and signed JWT
=================================

This example shows how a JWT can be signed and encrypted by a common shared key.

Goal
----------------------
- (**REQ.1**) Integrity protect a JWT
- (**REQ.2**) Protect confidentiality of the JWT
- (**REQ.3**) Allow the same secret (shared) key to be used for both

### Example output

```text
Shared secret              : [-46, 95, 30, 15, -18, 7, 114, 39, 102, 103, -118, 17, -87, -16, 5, 61, -91, -97, -110, -24, -125, -6, 10, 97, -96, 60, 72, 15, -1, 101, -88, 117]
Example derived 4-byte key for K.1: [69, 12, 123, 111]
Example derived 4-byte key for K.2: [69, 39, -57, 52]
Signed JWT      | Signed JWT (len: 225)   : eyJraWQiOiIxIiwiYWxnIjoiSFMyNTYifQ.eyJpc3MiOiJBQ01FIENvcnBcL2RlbW8tY2FzZVwvVEVTVCIsInN1YiI6IkpvaG4gRG9lIiwiYXVkIjoiQUNNRSBDb3JwXC9kZW1vLWF1ZGllbmNlXC9URVNUIiwiZXhwIjoxNjQ4NDU3MzcxfQ.t03KaYVm_swA_05xxwa0hJ24baYjqXPIp8_6VHI1Di8
Signed JWT      | Signed & Enc JWT (len: 394; 169 bytes overhead): eyJraWQiOiIxIiwiZW5jIjoiQTEyOEdDTSIsImFsZyI6ImRpciJ9..KaJrTe289riNlxB2.6uevjfB60mK0JGtawyVWwzJOoehPL4F1DCe4zGLrSkcjcHDQNCfY2b43JFmaOGSOGha1iB54iG2DhhT8QSo5gkKmaWRwy_YmvdhuXWKqXkpDfqPU2ExpXVB56bpFi-RHW0gvkpGeV83EChaA24e98uRq0Wc2PfLVeAbfnObHGaiFr1x3ozMsYJHqF0S3jJBf4o3kq-Dlgo8-aas9Pc5ktdwpnhEL4sbbKDyijlIpOlocY6nw236mqhrJvBEzAmXh1jqoI7FW66x_jQ7NTCFiPc7GF7qoZo5GaQShwQJ5gtCl.MEeRf_NjtPtBs9yX2itoYQ
Signed JWT      | Parsed JWT: eyJraWQiOiIxIiwiYWxnIjoiSFMyNTYifQ.eyJpc3MiOiJBQ01FIENvcnBcL2RlbW8tY2FzZVwvVEVTVCIsInN1YiI6IkpvaG4gRG9lIiwiYXVkIjoiQUNNRSBDb3JwXC9kZW1vLWF1ZGllbmNlXC9URVNUIiwiZXhwIjoxNjQ4NDU3MzcxfQ.t03KaYVm_swA_05xxwa0hJ24baYjqXPIp8_6VHI1Di8
Signed JWT      | Parsed JWT: Hello, John Doe
Unsigned JWT    | Unsigned JWT (len: 167  : eyJhbGciOiJub25lIn0.eyJpc3MiOiJBQ01FIENvcnBcL2RlbW8tY2FzZVwvVEVTVCIsInN1YiI6IkpvaG4gRG9lIiwiYXVkIjoiQUNNRSBDb3JwXC9kZW1vLWF1ZGllbmNlXC9URVNUIiwiZXhwIjoxNjQ4NDU3MzcxfQ.
Unsigned JWT    | Signed & Enc JWT (len: 317; 150 bytes overhead): eyJraWQiOiIxIiwiZW5jIjoiQTEyOEdDTSIsImFsZyI6ImRpciJ9..RtUzph-XZ_LMifF6.hxjmsLib7zboMv2drQj93pUmGbox3PDpqzBqww1iH0HRqey7JlI0ueONxUfEt8sajAqn9_1lGeTkw_zFC45_g420DepcaULH5_Z2LToJvaM74SuXGImiHyWf2oNhIusNjgmjIOwa0tnAoG_eZfLWldypnXrkHfYHa2hQcvyHBgKO_15eG7vYjcN2hNzG9zkfP-oybXB5YEvyNw2VRFjm6gQp4KfZSMM.Nme7US4lhDiK5fHeEq-7kg

```
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

