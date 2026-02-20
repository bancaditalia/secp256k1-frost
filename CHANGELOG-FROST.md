# Changelog - FROST module

## [0.6.0-frost-1] - 2026-02-19

#### Changed
 - rebased on secp256k1 **v0.6.0**
 - replace `memset()` with `secp256k1_memclear()` (a new function introduced in v0.6.0) where possible
 - clear more temporaries in `generate_dkg_challenge()` and `compute_challenge()`
 - updated base CI images for the FROST module

#### Fixed
 - Valgrind is not well supported under MacOS. Disable running FROST under Valgrind on MacOS in the CI

## [0.5.1-frost-2] - 2026-02-18

#### Added
 - benchmark for FROST module
 - ci: also test CMake builds under Valgrind
 - ci: check version consistency among Autotools and CMake builds

#### Changed
 - improved documentation of the public FROST API in `include/secp256k1_frost.h`
 - use an equivalent but more efficient formula in `secp256k1_frost_verify()`
 - ci: added the possibility of manually triggering a CI run
 - canonicalized parameter order in internal functions
 - use uniform parameter names in the module
 - introduced a return code for `secp256k1_frost_gej_serialize_compact()`
 - clear temporaries in `secp256k1_frost_keygen_dkg_begin()` and `secp256k1_frost_gej_serialize_compact()`
 - removed redundant code in `secp256k1_frost_aggregate()`, `encode_group_commitments()`, `generate_dkg_challenge()`

#### Fixed
 - fixed compilation warning under clang-22
 - fix documentation inconsistencies

## [0.5.1-frost-1] - 2025-07-04

Merge `secp256k1` v0.5.1. 

#### Added
- CI: add frost-specific configuration to cirrus.yml workflow
- CI: build frost on CI workflow `arm64-macos-native`

#### Changed
- CI: update config parameters in frost-on-windows workflow

#### Fixed
- use array initialization for unterminated strings in `testrand_seed()` (this is not frost-specific)

## [0.5.0-frost-1] - 2025-05-30

Merge `secp256k1` v0.5.0. 
Breaking change to `secp256k1_frost_sign()` API.

#### Added
- add `secp256k1_context` as parameter of `secp256k1_frost_sign()`. This breaks API compatibility.

#### Changed
- replace `signing_commitment_sort()` with `secp256k1_hsort()` 

## [0.4.1-frost-1] - 2025-05-30

Merge `secp256k1` v0.4.1. No changes to the frost module. 

## [0.4.0-frost-1] - 2025-05-21

Merge `secp256k1` v0.4.0. 

#### Added
- CI: enable FROST in the official CI pipeline

#### Changed 
- use array initialization for unterminated strings
- prefix with "frost-" all workflows not coming from upstream
- CI: use `fedora:42` to compile using `gcc-15.1`

#### Fixed
- CI: fix compilation of frost module with gcc 15 

## [0.3.2-frost-1] - 2025-04-08

Merge `secp256k1` v0.3.2. 

#### Added
- CI: add build for Windows

#### Changed
- use `secp256k1_scalar_one` instead of allocating on the stack
- use `secp256k1_scalar_clear()` instead of setting to 0
- remove redundant secp256k1_gej_mul_scalar() when the first factor is infinity
- CI: update runner and builder images to `ubuntu:24.04` and `fedora:41`

#### Fixed
- fix build on Windows (use `bcrypt` when compiling with `MinGW`)

## [0.3.1-frost-1] - 2023-11-27

Merge `secp256k1` v0.3.1. 

#### Changed
- error checking in `deserialize_frost_signature()`

## [0.3.0-frost-1] - 2023-11-23

Merge `secp256k1` v0.3.0. 

#### Added
- CI: add github workflow to build also with CMake 
- CI: ensure that number versioning matches in `configure.ac` and `CMakeLists.txt` 

## [0.2.0-frost-1] - 2023-11-21

Merge `secp256k1` v0.2.0. No changes to the frost module. 

## [0.1.0-frost-1] - 2023-06-30

#### Added
- run FROST tests and example under Valgrind 
  
#### Changed
- rename the functinal-tests.yml workflow 

## [0.1.0-pre-frost-1] - 2023-06-16

Code review and merge `secp256k1` from `bitcoin` v23 to v24.

#### Added
- add `secp256k1_frost_pubkey_save()` and `secp256k1_frost_pubkey_load()`
- run functional tests of frost module in continuous integration (CI)
- add copyright banner 

#### Changed
- initialize `secp256k1_gej` to infinity instead of invalid
- remove `rho_input` as parameter of `compute_binding_factor()`; no changes to APIs
- update prefix of h1, h2, h3, h4, h5 hash functions
- review documentation
- code reformat

#### Fixed
- fix potential memory leak in `secp256k1_frost_aggregate()`
- remove potentail free or null pointer when using custom error_handler
  
## [0.1.0-frost-0] - 2023-05-09

This version was in fact never released.
Commit `c31b9c193c3826d683ca58260ae1933dcc1a6eb6` introduces the first implementation FROST as a 
module of secp256k1. 

[0.6.0-frost-1]: https://github.com/bancaditalia/secp256k1-frost/compare/v0.5.1-frost-2...v0.6.0-frost-1
[0.5.1-frost-2]: https://github.com/bancaditalia/secp256k1-frost/compare/v0.5.1-frost-1...v0.5.1-frost-2
[0.5.1-frost-1]: https://github.com/bancaditalia/secp256k1-frost/compare/v0.5.0-frost-1...v0.5.1-frost-1
[0.5.0-frost-1]: https://github.com/bancaditalia/secp256k1-frost/compare/v0.4.1-frost-1...v0.5.0-frost-1
[0.4.1-frost-1]: https://github.com/bancaditalia/secp256k1-frost/compare/v0.4.0-frost-1...v0.4.1-frost-1
[0.4.0-frost-1]: https://github.com/bancaditalia/secp256k1-frost/compare/v0.3.2-frost-1...v0.4.0-frost-1
[0.3.2-frost-1]: https://github.com/bancaditalia/secp256k1-frost/compare/v0.3.1-frost-1...v0.3.2-frost-1
[0.3.1-frost-1]: https://github.com/bancaditalia/secp256k1-frost/compare/v0.3.0-frost-1...v0.3.1-frost-1
[0.3.0-frost-1]: https://github.com/bancaditalia/secp256k1-frost/compare/v0.2.0-frost-1...v0.3.0-frost-1
[0.2.0-frost-1]: https://github.com/bancaditalia/secp256k1-frost/compare/v0.1.0-frost-1...v0.2.0-frost-1
[0.1.0-frost-1]: https://github.com/bancaditalia/secp256k1-frost/compare/v0.1.0-pre-frost-1...v0.1.0-frost-1
[0.1.0-pre-frost-1]: https://github.com/bancaditalia/secp256k1-frost/compare/c31b9c193c3826d683ca58260ae1933dcc1a6eb6...v0.1.0-pre-frost-1
[0.1.0-frost-0]: https://github.com/bancaditalia/secp256k1-frost/commit/c31b9c193c3826d683ca58260ae1933dcc1a6eb6
