/***********************************************************************
 * Copyright (c) 2023 Bank of Italy                                    *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_FROST_H
#define SECP256K1_FROST_H

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

/* ------ Data structures ------ */
typedef struct {
    uint32_t generator_index;
    uint32_t receiver_index;
    unsigned char value[32];
} secp256k1_frost_keygen_secret_share;

typedef struct {
    unsigned char data[64];
} secp256k1_frost_vss_commitment;

typedef struct {
    uint32_t index;
    uint32_t num_coefficients;
    secp256k1_frost_vss_commitment *coefficient_commitments;
    unsigned char zkp_r[64];
    unsigned char zkp_z[32];
} secp256k1_frost_vss_commitments;

typedef struct {
    uint32_t index;
    unsigned char hiding[64];
    unsigned char binding[64];
} secp256k1_frost_nonce_commitment;

typedef struct {
    int used; /* 1 if true, 0 if false */
    unsigned char hiding[32];
    unsigned char binding[32];
    secp256k1_frost_nonce_commitment commitments;
} secp256k1_frost_nonce;

typedef struct {
    uint32_t index;
    uint32_t max_participants;
    unsigned char public_key[64];
    unsigned char group_public_key[64];
} secp256k1_frost_pubkey;

typedef struct {
    unsigned char secret[32];
    secp256k1_frost_pubkey public_keys;
} secp256k1_frost_keypair;

typedef struct {
    uint32_t index;
    unsigned char response[32];
} secp256k1_frost_signature_share;

/* ------ Keygen-related functions ------ */

/*
 * Initialize secp256k1_frost_keypair using the compact (33-bytes) representation of public keys.
 *  Returns 1 on success, 0 on failure.
 *  Out:          pubkey: pointer to a secp256k1_frost_pubkey to update.
 *  In:            index: identifier of participant.
 *      max_participants: maximum number of participants (coherent with group public key).
 *              pubkey33: pointer to compact public key (33 bytes).
 *        group_pubkey33: pointer to compact group public key (33 bytes).
 */
SECP256K1_API int secp256k1_frost_pubkey_load(
    secp256k1_frost_pubkey *pubkey,
    const uint32_t index,
    const uint32_t max_participants,
    const unsigned char *pubkey33,
    const unsigned char *group_pubkey33
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5);

/*
 * Return the compact (33-bytes) representation of the public keys in secp256k1_frost_keypair.
 *  Returns 1 on success, 0 on failure.
 *  Out:        pubkey33: pointer to a 33-byte array where the public key will be stored.
 *        group_pubkey33: pointer to a 33-byte array where the group public key will be stored.
 *  In:           pubkey: pointer to an initialized secp256k1_frost_pubkey.
 */
SECP256K1_API int secp256k1_frost_pubkey_save(
    unsigned char *pubkey33,
    unsigned char *group_pubkey33,
    const secp256k1_frost_pubkey *pubkey
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/*
 * Initialize a secp256k1_frost_pubkey using information in secp256k1_frost_keypair.
 *  Returns 1 on success, 0 on failure.
 *  Out:   pubkey: pointer to a secp256k1_frost_pubkey to update.
 *  In:   keypair: pointer to an initialized secp256k1_frost_keypair.
 */
SECP256K1_API int secp256k1_frost_pubkey_from_keypair(
    secp256k1_frost_pubkey *pubkey,
    const secp256k1_frost_keypair *keypair
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2);

/*
 * Create a secp256k1 frost vss_commitments object (in dynamically allocated memory).
 *  This function uses malloc to allocate memory.
 *
 *  Returns: a newly created vss_commitments object.
 *  In:     threshold: minimum number of participants needed to compute a valid signature.
 */
SECP256K1_API secp256k1_frost_vss_commitments *secp256k1_frost_vss_commitments_create(
    uint32_t threshold
);

/*
 * Destroy a secp256k1 vss_commitments object (created in dynamically allocated memory).
 *
 *  The vss_commitments pointer should not be used afterwards.
 *
 *  The nonce to destroy must have been created using secp256k1_frost_nonce_create.
 *  Args:   vss_commitments: an existing vss_commitments to destroy,
 *                           constructed using secp256k1_frost_vss_commitments_create
 */
SECP256K1_API void secp256k1_frost_vss_commitments_destroy(
    secp256k1_frost_vss_commitments *vss_commitments
) SECP256K1_ARG_NONNULL(1);

/*
 * Create a secp256k1 frost nonce object (in dynamically allocated memory).
 *
 *  This function uses malloc to allocate memory.
 *
 *  Returns: a newly created nonce object.
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
 *  Destroy a secp256k1 nonce object (created in dynamically allocated memory).
 *
 *  The context pointer should not be used afterwards.
 *
 *  The nonce to destroy must have been created using secp256k1_frost_nonce_create.
 *  Args:   nonce: an existing nonce to destroy, constructed using
 *               secp256k1_frost_nonce_create
 */
SECP256K1_API void secp256k1_frost_nonce_destroy(
    secp256k1_frost_nonce *nonce
) SECP256K1_ARG_NONNULL(1);

/*
 * Create a secp256k1 frost keypair object (in dynamically allocated memory).
 *
 *  This function uses malloc to allocate memory.
 *
 *  Returns: a newly created keypair object.
 *  Args:         ctx: pointer to a context object, initialized for signing.
 */
SECP256K1_API secp256k1_frost_keypair *secp256k1_frost_keypair_create(
    uint32_t participant_index
);

/*
 * Destroy a secp256k1 frost keypair object (created in dynamically allocated memory).
 *
 *  The context pointer should not be used afterwards.
 *
 *  The keypair to destroy must have been created using secp256k1_frost_keypair_create.
 *  Args:   nonce: an existing keypair to destroy, constructed using secp256k1_frost_keypair_create
 */
SECP256K1_API void secp256k1_frost_keypair_destroy(
    secp256k1_frost_keypair *keypair
) SECP256K1_ARG_NONNULL(1);

/*
 * secp256k1_frost_keygen_dkg_begin() is performed by each participant to initialize a Pedersen
 *
 * This function assumes there is an additional layer which performs the
 * distribution of secret_key_shares to their intended participants.
 *
 * Note that while secp256k1_frost_keygen_dkg_begin() returns Shares, these secret_key_shares
 * should be sent *after* participants have exchanged commitments via
 * secp256k1_frost_keygen_dkg_commitment_validate(). So, the caller of
 * secp256k1_frost_keygen_dkg_begin() should store secret_key_shares until after
 * secp256k1_frost_keygen_dkg_commitment_validate() is complete, and then
 * exchange secret_key_shares via secp256k1_frost_keygen_dkg_finalize().
 *
 *  Returns 1 on success, 0 on failure.
 *  Args:            ctx: pointer to a context object, initialized for signing.
 *  Out:  vss_commitments: pointer to a secp256k1_frost_vss_commitments to store the DKG first phase result.
 *      secret_key_shares: pointer to an array of num_shares secret_key_shares
 *  In:  num_participants: number of participants and secret_key_shares that will be produced.
 *              threshold: validity threshold for signatures.
 *        generator_index: index of the participant running the DKG.
 *                context: pointer to a char array containing DKG context tag.
 *         context_length: length of the char array with the DKG context.
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
 * secp256k1_frost_keygen_dkg_commitment_validate() gathers commitments from
 * peers and validates the zero knowledge proof of knowledge for the peer's
 * secret term. It returns a list of all participants who failed the check, a
 * list of commitments for the peers that remain in a valid state, and an error
 * term.
 *
 * Here, we return a DKG commitment that is explicitly marked as valid, to
 * ensure that this step of the protocol is performed before going on to
 * secp256k1_frost_keygen_dkg_finalize().
 *
 * Returns 1 on success, 0 on failure.
 *  Args:                        ctx: pointer to a context object, initialized for signing.
 *  In:              peer_commitment: pointer to commitment to validate.
 *                           context: pointer to a char array containing DKG context tag.
 *                    context_length: length of the char array with the DKG context.
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_frost_keygen_dkg_commitment_validate(
        const secp256k1_context *ctx,
        const secp256k1_frost_vss_commitments *peer_commitment,
        const unsigned char *context,
        uint32_t context_length
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/*
 * secp256k1_frost_keygen_dkg_finalize() finalizes the distributed key generation protocol.
 * It is performed once per participant.
 *
 * Returns 1 on success, 0 on failure.
 *  Args:            ctx: pointer to a context object, initialized for signing.
 *  Out:         keypair: pointer to a frost_keypair to store the generated keypairs.
 *  In:            index: participant index.
 *      num_participants: number of shares and commitments.
 *                shares: shares of the current participant.
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
 * secp256k1_frost_keygen_with_dealer() allows to create keygen for each participant.
 * This function is intended to be executed by a trusted dealer that generates and
 * distributes the secret secret_key_shares.
 *
 *  Returns 1 on success, 0 on failure.
 *  Args:             ctx: pointer to a context object, initialized for signing.
 *  Out:  vss_commitments: pointer to a secp256k1_frost_vss_commitments to store the dealer commitments.
 *      secret_key_shares: pointer to an array of num_shares shares
 *               keypairs: pointer to a frost_keypair to store the generated keypairs.
 *  In:  num_participants: number of participants and shares that will be produced.
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

/* ------ Signing-related functions ------ */

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
 *  Returns 1 on success, 0 on failure.
 *  Args:          ctx: pointer to a context object, initialized for signing.
 *  Out:         sig64: pointer to a 64-byte array for the serialized signature.
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
        unsigned char *sig64,
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
 *  In:      sig64: pointer to a byte array holding the signature to verify.
 *             msg: pointer the message that was signed.
 *      msg_length: the length of the message in bytes.
 *          pubkey: pointer to group public key.
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_frost_verify(
        const secp256k1_context *ctx,
        const unsigned char *sig64,
        const unsigned char *msg,
        uint32_t msg_length,
        const secp256k1_frost_pubkey *pubkey
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(5);

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_FROST_H */
