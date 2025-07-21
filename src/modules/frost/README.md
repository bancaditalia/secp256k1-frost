# FROST: Flexible Round-Optimized Schnorr Threshold Signatures

This module implements the threshold signature scheme FROST, standardized by the IETF as [RFC-9591](https://doi.org/10.17487/RFC9591).

Originally designed in 2020 by Chelsea Komlo and Ian Goldberg,
FROST was first presented at the International Conference on Selected Areas in Cryptography:

> C. Komlo and I. Goldberg, "FROST: Flexible Round-Optimized Schnorr Threshold Signatures".
> International Conference on Selected Areas in Cryptography, 2020, Springer.
> https://doi.org/10.1007/978-3-030-81652-0_2

A technical report describing the protocol with further details is available at
the [Cryptology ePrint Archive (Paper 2020/852)](https://eprint.iacr.org/2020/852).

The protocol was later standardized through the IETF process.
More information is available on the [IETF Datatracker](https://datatracker.ietf.org/doc/draft-irtf-cfrg-frost/) page.

This implementation integrates FROST into [secp256k1](https://github.com/bitcoin-core/secp256k1), 
a cryptographic library optimized for the secp256k1 elliptic curve.
As per [RFC-9591](https://www.rfc-editor.org/rfc/rfc9591.html#name-frostsecp256k1-sha-256), 
the protocol is defined over this curve and uses SHA-256.

The FROST module was originally developed by the Bank of Italy as part of the [itcoin project](https://bancaditalia.github.io/itcoin/).
It now fully supports RFC 9591 and includes the official test vectors for compliance verification.

## Build

FROST is implemented as a module of the secp256k1 library. Currently, it is an experimental module.
To enable FROST, configure with `--enable-module-frost`:

    $ ./configure --enable-module-frost --enable-experimental

This library aims to have full coverage of the reachable lines and branches, also for the FROST module.
Run the tests:

    $ make check

### Building with CMake on POSIX systems

To maintain a pristine source tree, CMake encourages to perform an out-of-source build by using a separate dedicated build tree.

    $ mkdir build && cd build
    $ cmake -DSECP256K1_ENABLE_MODULE_FROST=ON -DSECP256K1_EXPERIMENTAL=ON ..
    $ make
    $ make check  # run the test suite
    $ sudo make install  # optional

To compile the FROST module, you need to run `cmake` with the additional flags `-DSECP256K1_ENABLE_MODULE_FROST=ON -DSECP256K1_EXPERIMENTAL=ON`.
Run `cmake .. -LH` to see the full list of available flags.

## Usage example

A [FROST usage example](../../../examples/frost.c) can be found in the [examples](../../../examples) directory.

To compile the examples, you need to configure with `--enable-examples` (or, the `cmake` flag `-DSECP256K1_BUILD_EXAMPLES=ON`).
Specifically, to compile the [FROST example](../../../examples/frost.c), you also need to configure with `--enable-module-frost`. If `cmake` is used, you need to provide the `-DSECP256K1_ENABLE_MODULE_FROST=ON -DSECP256K1_EXPERIMENTAL=ON` flags.

## Compliance with the IETF Standardized version of FROST

FROST is an experimental module of the secp256k1 library.

### IETF Standard

We refer to [draft v12](https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-12.html) of the IETF standardization proposal of FROST.

#### Helper Functions (Section 4 of IETF Standard)

- [x] `nonce_generate()`: our implementation expects to receive random 32-byte as a parameter (we want to remove dependencies from random generators)
- [x] `derive_interpolating_value()`
- [x] `encode_group_commitment_list()`: in our implementation, this function is named `encode_group_commitments()`
- [x] `participants_from_commitment_list()`: in our implementation, it is implemented using arrays
- [x] `binding_factor_for_participant()`
- [x] `compute_binding_factors()`
- [x] `compute_group_commitment()`
- [x] `compute_challenge()`

#### Two-Round FROST Signing Protocol (Section 5 of IETF Standard)

- [x] `commit()`: in our implementation, this function is named `secp256k1_frost_nonce_create()`
- [x] `sign()`: in our implementation, this function is named `secp256k1_frost_sign()`
- [x] `aggregate()`: in our implementation, this function is named `secp256k1_frost_aggregate()`
- [x] `verify_signature_share()`

#### Ciphersuite (Section 6 of IETF Standard)

This library only implements `FROST(secp256k1, SHA-256)`.
- [x] Group: secp256k1
- [x] Hash, H1(m): requires hash-to-curve
- [x] Hash, H2(m): requires hash-to-curve
- [x] Hash, H3(m): requires hash-to-curve
- [x] Hash, H4(m)
- [x] Hash, H5(m)


### secp256k1-frost

The `FROST` module of `secp256k1-frost` implements supplementary functions, which are not included in the version of FROST under standardization.
The following list keeps track of such functions.

#### Keygen

The IETF standard does not include a distributed key generation protocol.
This library implements the DKG protocol described in the [FROST paper](https://eprint.iacr.org/2020/852) and implemented
by Chelsea Komlo in the prototype [FROST repository](https://git.uwaterloo.ca/ckomlo/frost/).

- `secp256k1_frost_keygen_dkg_begin()`
- `secp256k1_frost_keygen_dkg_commitment_validate()`
- `secp256k1_frost_keygen_dkg_finalize()`

#### Signature

- `secp256k1_frost_sign()`: produce a signature share.
- `secp256k1_frost_aggregate()`: aggregate signature shares. Differently from the standard,
our implementation verifies each signature share before computing the aggregated signature
- `secp256k1_frost_verify()`: verify an aggregated signature. This is equivalent to a 
traditional Schnorr verification (e.g., as implemented in `secp256k1_schnorrsig_verify()`)

### BIP-340 Mode

To retain compatibility with BIP-340, our module supports tweaking points and encoding only the x-only coordinates of points.
This functionality is expressed by compiling the library with the flag `--enable-module-frost-bip340-mode`
(or, the `cmake` flag `-DSECP256K1_ENABLE_MODULE_FROST_BIP340_MODE=ON`)

- `secp256k1_frost_sign()`: to follow BIP-340, it adjusts the signature if the group commitment is odd
- `secp256k1_frost_aggregate()`: to follow BIP-340, it returns the group commitment with even y coordinate.
                                In this case, the signature is a 64-byte array (instead of a 65-byte array).
- Internally, `compute_challenge()` initializes SHA256 with fixed midstate (SHA256("BIP0340/challenge")||SHA256("BIP0340/challenge"))
