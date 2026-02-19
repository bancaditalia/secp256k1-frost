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

[0.6.0-frost-1]: https://github.com/bancaditalia/secp256k1-frost/compare/v0.5.1-frost-2...v0.6.0-frost-1
[0.5.1-frost-2]: https://github.com/bancaditalia/secp256k1-frost/compare/v0.5.1-frost-1...v0.5.1-frost-2
