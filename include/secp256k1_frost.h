/***********************************************************************
 * Copyright (c) 2023 Bank of Italy                                    *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_FROST_H
#define SECP256K1_FROST_H

/*******************************************************
 * SECTION: Overview
 *******************************************************/

/* This module provides an implementation of the two-round FROST signing protocol.
 *
 * FROST is described in https://eprint.iacr.org/2020/852 by Komlo and Goldberg.
 * Later, the IETF standardized the protocol under the RFC 9591
 * (https://www.rfc-editor.org/rfc/rfc9591).
 *
 * FROST signatures can be issued after a threshold number of entities cooperate to compute
 * a signature, allowing for improved distribution of trust and redundancy with respect to
 * a secret key. FROST depends only on a prime-order group and cryptographic hash function.
 *
 * The implementation of FROST included in this module uses secp256k1 for the group and
 * SHA-256 for computing the hash functions.
 */

/*
 * The following inclusions are needed to bring uint32_t in scope in a platform
 * and language independent way.
 * Without this snippet the following commands would fail:
 *     gcc -xc++ -c -Werror -pedantic-errors -include include/secp256k1_frost.h /dev/null -o /dev/null
 *     gcc -xc   -c -Werror -pedantic-errors -include include/secp256k1_frost.h /dev/null -o /dev/null
 *
 * references:
 *     scripts/ensure-frost-header-is-precompilable.sh
 *     https://gcc.gnu.org/bugzilla/show_bug.cgi?id=108732#c2 (for the gcc invocation syntax)
 */
#ifdef __cplusplus
    #include <cstdint>
#else
    #include <stdint.h>
#endif

#include "secp256k1.h"
#include "secp256k1_extrakeys.h"

#ifdef __cplusplus
extern "C" {
#endif

/*******************************************************
 * SECTION: Data Structures
 *******************************************************/

#ifdef ENABLE_MODULE_FROST_BIP340_MODE
    /* BIP340 mode */
    #define FROST_SIGNATURE_SIZE   (64)
#else
    /* RFC9591 mode */
    #define FROST_SIGNATURE_SIZE   (65)
#endif /* ENABLE_MODULE_FROST_BIP340_MODE */

/* Share of the group secret key.
 *
 * The secret share results from evaluating the (generator) Shamir polynomial in the receiver index point.
 */
typedef struct {
    uint32_t generator_index;
    uint32_t receiver_index;
    unsigned char value[32];
} secp256k1_frost_keygen_secret_share;

typedef struct {
    unsigned char data[64];
} secp256k1_frost_vss_commitment;

/* Zero-knowledge proof of knowledge for of secret Shamir polynomial coefficients. */
typedef struct {
    uint32_t index;
    uint32_t num_coefficients;
    secp256k1_frost_vss_commitment *coefficient_commitments;
    unsigned char zkp_r[64];
    unsigned char zkp_z[32];
} secp256k1_frost_vss_commitments;

/* Commitment to nonce used for signing. */
typedef struct {
    uint32_t index;
    unsigned char hiding[64];
    unsigned char binding[64];
} secp256k1_frost_nonce_commitment;

/* Nonce used for signing. */
typedef struct {
    int used; /* 1 if true, 0 if false */
    unsigned char hiding[32];
    unsigned char binding[32];
    secp256k1_frost_nonce_commitment commitments;
} secp256k1_frost_nonce;

/* Opaque representation of a FROST public key */
typedef struct {
    uint32_t index;
    uint32_t max_participants;
    unsigned char public_key[64];
    unsigned char group_public_key[64];
} secp256k1_frost_pubkey;

/* Participant keypair used for signing.
 *
 * This structure holds the participant's secret key share.
 */
typedef struct {
    unsigned char secret[32];
    secp256k1_frost_pubkey public_keys;
} secp256k1_frost_keypair;

/* Representation of a FROST signature share  */
typedef struct {
    uint32_t index;
    unsigned char response[32];
} secp256k1_frost_signature_share;

/*******************************************************
 * SECTION: Data management (Key, nonce, and commitment)
 *******************************************************/
/*
 * Initialize a participant's public keys from compact (33-bytes) serialized keys.
 *
 * Used to load key material from external storages.
 *
 *  Returns 1 on success, 0 on failure.
 *  Out:          pubkey: pointer to the destination secp256k1_frost_pubkey structure.
 *  In:            index: participant index.
 *      max_participants: total number of participants.
 *              pubkey33: pointer to the compact (33-bytes) participant public key.
 *        group_pubkey33: pointer to the compact (33-bytes) group public key.
 */
SECP256K1_API int secp256k1_frost_pubkey_load(
    secp256k1_frost_pubkey *pubkey,
    const uint32_t index,
    const uint32_t max_participants,
    const unsigned char *pubkey33,
    const unsigned char *group_pubkey33
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5);

/*
 * Export public key material to compact (33-bytes) format
 *
 * Returns 1 on success, 0 on failure.
 *  Out:        pubkey33: pointer to a 33-byte array where the participant public key will be stored.
 *        group_pubkey33: pointer to a 33-byte array where the group public key will be stored.
 *  In:           pubkey: pointer to an initialized secp256k1_frost_pubkey.
 */
SECP256K1_API int secp256k1_frost_pubkey_save(
    unsigned char *pubkey33,
    unsigned char *group_pubkey33,
    const secp256k1_frost_pubkey *pubkey
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/*
 * Derive a secp256k1_frost_pubkey structure from a given keypair (`secp256k1_frost_keypair`).
 *
 *  Returns 1 on success, 0 on failure.
 *  Out:   pubkey: pointer to a secp256k1_frost_pubkey to update.
 *  In:   keypair: pointer to an initialized secp256k1_frost_keypair.
 */
SECP256K1_API int secp256k1_frost_pubkey_from_keypair(
    secp256k1_frost_pubkey *pubkey,
    const secp256k1_frost_keypair *keypair
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2);

/*
 * Create a Verifiable Secret Sharing (VSS) commitments container.
 *
 *  Dynamically allocates memory to hold polynomial commitments used in key generation.
 *  This function uses malloc to allocate memory.
 *
 *  Returns: a newly created vss_commitments object.
 *  In:     threshold: minimum number of participants needed to compute a valid signature.
 */
SECP256K1_API secp256k1_frost_vss_commitments *secp256k1_frost_vss_commitments_create(
    uint32_t threshold
);

/*
 * Destroy a VSS commitments container previously created by `secp256k1_frost_vss_commitments_create()`.
 *
 *  The vss_commitments pointer should not be used afterward.
 *
 *  Args:   vss_commitments: an existing vss_commitments to destroy,
 *                           constructed using secp256k1_frost_vss_commitments_create
 */
SECP256K1_API void secp256k1_frost_vss_commitments_destroy(
    secp256k1_frost_vss_commitments *vss_commitments
) SECP256K1_ARG_NONNULL(1);

/*
 * Create fresh FROST nonce for signing.
 *
 *  Generates two random nonces (hiding and binding) and their corresponding
 *  public commitments. Nonces must never be reused.
 *  This function uses malloc to allocate memory.
 *
 *  Returns: pointer to a newly allocated nonce object.
 *  Args:         ctx: pointer to a context object, initialized for signing.
 *  In:       keypair: pointer to an initialized keypair.
 *     binding_seed32: pointer to a 32-byte random seed (NULL resets to initial state)
 *      hiding_seed32: pointer to a 32-byte random seed (NULL resets to initial state)
 */
SECP256K1_API secp256k1_frost_nonce *secp256k1_frost_nonce_create(
        const secp256k1_context *ctx,
        const secp256k1_frost_keypair *keypair,
        const unsigned char *binding_seed32,
        const unsigned char *hiding_seed32
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2);

/*
 * Destroy a FROST nonce created with secp256k1_frost_nonce_create().
 *
 *  The nonce pointer should not be used afterward.
 *
 *  Args:   nonce: an existing nonce to destroy.
 */
SECP256K1_API void secp256k1_frost_nonce_destroy(
    secp256k1_frost_nonce *nonce
) SECP256K1_ARG_NONNULL(1);

/*
 * Create a participant keypair object.
 *
 *  Allocates and initializes a keypair structure for the given participant index.
 *  This function uses malloc to allocate memory.
 *
 *  Returns: pointer to the new keypair object.
 *  Args:         ctx: pointer to a context object, initialized for signing.
 */
SECP256K1_API secp256k1_frost_keypair *secp256k1_frost_keypair_create(
    uint32_t participant_index
);

/*
 * Destroy a keypair object previously created by secp256k1_frost_keypair_create().
 *
 *  The keypair pointer should not be used afterward.
 *
 *  Args:   nonce: an existing keypair to destroy.
 */
SECP256K1_API void secp256k1_frost_keypair_destroy(
    secp256k1_frost_keypair *keypair
) SECP256K1_ARG_NONNULL(1);

/*******************************************************
* SECTION: Key Generation
*******************************************************/

/*
 * Begin the distributed key generation (DKG) – Phase 1: Commitment generation.
 *
 *  Each participant samples a random polynomial, produces its
 *  commitments and secret shares, and proves knowledge of its secret term.
 *
 *  Secret shares (secret_key_shares) must be stored locally and distributed only
 *  after commitments are exchanged and validated
 *  (using `secp256k1_frost_keygen_dkg_commitment_validate()`).
 *  Secret shares are exchanged via `secp256k1_frost_keygen_dkg_finalize()`.
 *
 *  Returns 1 on success, 0 on failure.
 *  Args:            ctx: pointer to a context object, initialized for signing.
 *  Out:  vss_commitments: pointer to a secp256k1_frost_vss_commitments to store the DKG first phase result.
 *      secret_key_shares: pointer to an array of num_shares secret_key_shares
 *  In:  num_participants: number of participants and secret_key_shares that will be produced.
 *              threshold: minimum number of participants needed to compute a valid signature.
 *        generator_index: index of the participant running the DKG.
 *                context: pointer to the DKG context tag.
 *         context_length: length of the DKG context in bytes.
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_frost_keygen_dkg_begin(
        const secp256k1_context *ctx,
        secp256k1_frost_vss_commitments *vss_commitments,
        secp256k1_frost_keygen_secret_share *secret_key_shares,
        uint32_t num_participants,
        uint32_t threshold,
        uint32_t generator_index,
        const unsigned char *context,
        uint32_t context_length
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(7);

/*
 * Validate commitments received from peers (DKG Phase 2).
 *
 *  Verifies the zero-knowledge proof of knowledge for each peer's secret
 *  coefficient. Participants failing validation are considered invalid and
 *  should be excluded from further rounds.
 *
 * Returns 1 on success, 0 on failure.
 *  Args:                        ctx: pointer to a context object, initialized for signing.
 *  In:              peer_commitment: pointer to commitment to validate.
 *                           context: pointer to the DKG context tag.
 *                    context_length: length of the DKG context in bytes.
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_frost_keygen_dkg_commitment_validate(
        const secp256k1_context *ctx,
        const secp256k1_frost_vss_commitments *peer_commitment,
        const unsigned char *context,
        uint32_t context_length
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/*
 * Finalize distributed key generation (DKG Phase 3).
 *
 *  Combines valid secret shares and commitments to derive each participant’s
 *  keypair (private share and corresponding public key). Must be called once per
 *  participant after all valid commitments and shares have been exchanged.
 *
 * Returns 1 on success, 0 on failure.
 *  Args:            ctx: pointer to a context object, initialized for signing.
 *  Out:         keypair: pointer to a secp256k1_frost_keypair where the participant's keypair is stored.
 *  In:            index: participant index.
 *      num_participants: number of shares and commitments.
 *                shares: secret shares received by the current participant during DKG.
 *           commitments: all participants' commitments exchanged during DKG.
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_frost_keygen_dkg_finalize(
        const secp256k1_context *ctx,
        secp256k1_frost_keypair *keypair,
        uint32_t index,
        uint32_t num_participants,
        const secp256k1_frost_keygen_secret_share *shares,
        secp256k1_frost_vss_commitments **commitments
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(6);

/*
 * Dealer-based key generation.
 *
 *  Performed by a trusted dealer who samples the group secret polynomial,
 *  computes commitments, and distributes valid secret shares and keypairs to
 *  participants.
 *
 *  Returns 1 on success, 0 on failure.
 *  Args:             ctx: pointer to a context object, initialized for signing.
 *  Out:  vss_commitments: pointer to the structure where the commitments of the Shamir polynomial coefficients will be stored.
 *      secret_key_shares: pointer to an array of `num_participant` secret key shares
 *               keypairs: pointer to an array where to store the generated keypairs for each participant.
 *  In:  num_participants: the number of participants and shares that will be produced.
 *              threshold: validity threshold for signatures.
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_frost_keygen_with_dealer(
        const secp256k1_context *ctx,
        secp256k1_frost_vss_commitments *vss_commitments,
        secp256k1_frost_keygen_secret_share *secret_key_shares,
        secp256k1_frost_keypair *keypairs,
        uint32_t num_participants,
        uint32_t threshold
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

/*******************************************************
 * SECTION: Signing
 *******************************************************/

/*
 * Create a FROST signature share.
 *
 * Each participant generates a signature share for a given message using its
 * private key, nonce, and the set of signing commitments of all participants.
 * This corresponds to "Round Two - Signature Share Generation" in RFC 9591 §5.2.
 *      https://www.rfc-editor.org/rfc/rfc9591#name-round-two-signature-share-g
 *
 * The resulting signature share must be sent back to the Coordinator for
 * aggregation. After producing the share, the signer MUST securely delete
 * the nonce and its corresponding commitment, as nonces must never be reused.
 *
 *  Returns 1 on success, 0 on failure.
 *  Args:             ctx: pointer to a context object, initialized for signing.
 *  Out:  signature_share: pointer to the struct that will hold the signature share.
 *  In:               msg: pointer to the message to be signed.
 *             msg_length: length of the message in bytes.
 *            num_signers: total number of signers participating in this round.
 *                keypair: pointer to an initialized keypair (participant's secret and public key).
 *                  nonce: pointer to an initialized nonce associated with this round.
 *    signing_commitments: pointer to an array of `num_signers` nonce commitments for all participants.
 *
 *  Notes:
 *   - Each signer must ensure its identifier and commitments appear in `signing_commitments`.
 *   - The nonce must not be reused for another signing session.
 */
SECP256K1_API int secp256k1_frost_sign(
        const secp256k1_context *ctx,
        secp256k1_frost_signature_share *signature_share,
        const unsigned char *msg,
        uint32_t msg_length,
        uint32_t num_signers,
        const secp256k1_frost_keypair *keypair,
        secp256k1_frost_nonce *nonce,
        secp256k1_frost_nonce_commitment *signing_commitments
) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(6) SECP256K1_ARG_NONNULL(7)
SECP256K1_ARG_NONNULL(8);

/*
 * Combine FROST signature shares into an aggregated signature.
 *
 * The Coordinator collects valid signature shares from participants and
 * aggregates them into a final signature (R, z), as defined in RFC 9591 §5.3.
 *      https://www.rfc-editor.org/rfc/rfc9591#name-signature-share-aggregation
 *
 * The signature size is defined in FROST_SIGNATURE_SIZE: when FROST is compiled
 * in BIP-340 mode, the signature size is 64 bytes. When it is compiled in
 * RFC9591 mode, it is 65 bytes.
 *
 *  Returns 1 on success, 0 on failure.
 *  Args:          ctx: pointer to a context object, initialized for signing.
 *  Out:     signature: pointer to a FROST_SIGNATURE_SIZE-bytes array for the serialized signature.
 *  In:            msg: pointer to the message that was signed.
 *          msg_length: length of the message in bytes.
 *             keypair: pointer to an initialized keypair of the coordinator (group info holder).
 *         public_keys: pointer to an array of all participating signers' public keys.
 *         commitments: pointer to an array of nonce commitments from the signers.
 *    signature_shares: pointer to an array of signature shares produced by the signers
 *         num_signers: number of signers contributing valid shares.
 *
 * Notes:
 *   - Before aggregation, each signature share is validated; invalid shares
 *     cause the aggregation to fail.
 *   - The resulting signature should be verified against the group public key
 *     using `secp256k1_frost_verify()` before publishing or releasing it.
 */
SECP256K1_API int secp256k1_frost_aggregate(
        const secp256k1_context *ctx,
        unsigned char *signature,
        const unsigned char *msg,
        uint32_t msg_length,
        const secp256k1_frost_keypair *keypair,
        const secp256k1_frost_pubkey *public_keys,
        secp256k1_frost_nonce_commitment *commitments,
        const secp256k1_frost_signature_share *signature_shares,
        uint32_t num_signers
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(5)
SECP256K1_ARG_NONNULL(6) SECP256K1_ARG_NONNULL(7) SECP256K1_ARG_NONNULL(8);

/*
 * Verify a FROST aggregate signature under the group public key.
 *
 * This function verifies that a FROST aggregate signature (R, z) is valid
 * for the given message and group public key, as specified in EFC 9591 §5.3.
 *      https://www.rfc-editor.org/rfc/rfc9591#name-signature-share-aggregation
 *
 * Typically used by the Coordinator (or external verifiers) after the
 * aggregation step to ensure the final signature is correct before publication.

 *  Returns 1 on success (correct signature), 0 on failure (incorrect signature).
 *  Args:      ctx: pointer to a secp256k1 context object, initialized for verification.
 *  In:  signature: pointer to a byte array holding the signature to verify.
 *             msg: pointer the message that was signed.
 *      msg_length: the length of the message in bytes.
 *          pubkey: pointer to group public key.
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_frost_verify(
        const secp256k1_context *ctx,
        const unsigned char *signature,
        const unsigned char *msg,
        uint32_t msg_length,
        const secp256k1_frost_pubkey *pubkey
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(5);

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_FROST_H */
