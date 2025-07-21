/***********************************************************************
 * Copyright (c) 2025 Bank of Italy                                    *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_FROST_TESTS_FROST_RFC9591_H
#define SECP256K1_MODULE_FROST_TESTS_FROST_RFC9591_H

#include "vectors/ietf_frost_rfc9591_test_vectors.h"

/*
 * Check FROST against IETF test vector for FROST(secp256k1, SHA-256)
 * See Appendix of:
 *  https://datatracker.ietf.org/doc/draft-irtf-cfrg-frost/
 */
void test_frost_rfc9591_test_vectors(void) {
    unsigned char group_public_key[33];
    secp256k1_gej group_public_key_gej;
    secp256k1_context *sign_ctx;
    secp256k1_frost_keypair keypairs[3];
    int result, i, j;
    uint32_t index;
    secp256k1_scalar secret;
    secp256k1_frost_nonce *nonces[IETF_FROST_MAX_PARTICIPANTS];
    secp256k1_frost_nonce_commitment signing_commitments[IETF_FROST_NUM_PARTICIPANTS];
    secp256k1_frost_signature_share signature_shares[IETF_FROST_NUM_PARTICIPANTS];
    secp256k1_frost_binding_factors binding_factors;

    /* Initialization */
    sign_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);

    /* **** **** IETF Test Vector: Signer and Group Input Parameters **** **** */
    /* Read group secret key from IETF test vector */
    secp256k1_scalar_set_b32(&secret, ietf_frost_group_secret_key, NULL);
    /* Compute group public key */
    secp256k1_ecmult_gen(&sign_ctx->ecmult_gen_ctx, &group_public_key_gej, &secret);
    /* Import secret and public keys for each participant */
    for (index = 0; index < IETF_FROST_MAX_PARTICIPANTS; index++) {
        secp256k1_scalar p_secret;
        secp256k1_gej p_pubkey;
        /* secret of participant with id: index + 1 */
        memcpy(&keypairs[index].secret,
               &ietf_frost_participant_shares[index * IETF_FROST_PARTICIPANT_SHARE_SIZE], SCALAR_SIZE);

        /* compute the participant's public key */
        secp256k1_scalar_set_b32(&p_secret, keypairs[index].secret, NULL);
        secp256k1_ecmult_gen(&sign_ctx->ecmult_gen_ctx, &p_pubkey, &p_secret);
        secp256k1_frost_gej_serialize(keypairs[index].public_keys.public_key, &p_pubkey);

        /* group public key and other info */
        secp256k1_frost_gej_serialize(keypairs[index].public_keys.group_public_key, &group_public_key_gej);
        keypairs[index].public_keys.index = index + 1;
        keypairs[index].public_keys.max_participants = IETF_FROST_MAX_PARTICIPANTS;
    }
    /* Check: Verify that the computed group public key matches the one in the test vector */
    result = secp256k1_frost_pubkey_serialize(group_public_key, keypairs[0].public_keys.group_public_key);
    CHECK(result == 1);
    result = memcmp(ietf_frost_group_public_key, group_public_key, 33);
    CHECK(result == 0);

    /* **** **** IETF Test Vector: Round One **** **** */
    /* Round one: compute nonce and commitments, using randomnesses from the test vector */
    for (i = 0; i < IETF_FROST_MAX_PARTICIPANTS; i++) {
        nonces[i] = secp256k1_frost_nonce_create(sign_ctx, &keypairs[i],
                                                 &ietf_frost_binding_nonce_randomnesses[i * IETF_FROST_BINDING_NONCE_RANDOMNESS_SIZE],
                                                 &ietf_frost_hiding_nonce_randomnesses[i * IETF_FROST_HIDING_NONCE_RANDOMNESS_SIZE]);
    }
    /* Round one: verify computed commitments against the test vector for participants: 1, 3 */
    for (j = 0; j < IETF_FROST_NUM_PARTICIPANTS; j++) {
        unsigned char buffer33[33];

        i = (int) ietf_frost_participants[j] - 1;
        result = memcmp(&ietf_frost_hiding_nonces[i * IETF_FROST_HIDING_NONCE_SIZE],
                        nonces[i]->hiding, IETF_FROST_HIDING_NONCE_SIZE);
        CHECK(result == 0);

        result = memcmp(&ietf_frost_binding_nonces[i * IETF_FROST_BINDING_NONCE_SIZE],
                        nonces[i]->binding, IETF_FROST_BINDING_NONCE_SIZE);
        CHECK(result == 0);

        secp256k1_frost_pubkey_serialize(buffer33, nonces[i]->commitments.hiding);
        result = memcmp(&ietf_frost_hiding_nonce_commitments[i * IETF_FROST_HIDING_NONCE_COMMITMENT_SIZE],
                        buffer33, IETF_FROST_HIDING_NONCE_COMMITMENT_SIZE);
        CHECK(result == 0);

        secp256k1_frost_pubkey_serialize(buffer33, nonces[i]->commitments.binding);
        result = memcmp(&ietf_frost_binding_nonce_commitments[i * IETF_FROST_BINDING_NONCE_COMMITMENT_SIZE],
                        buffer33, IETF_FROST_BINDING_NONCE_COMMITMENT_SIZE);
        CHECK(result == 0);
    }

    /* Round one: Since we have rho_input in the test vector, let's test whether H1 is computed as expected. */
    for (j = 0; j < IETF_FROST_NUM_PARTICIPANTS; j++) {
        unsigned char buf32[32];
        i = (int) ietf_frost_participants[j] - 1;
        /* Compute binding factor for participant (index): binding_factor = H1(rho_input) */
        compute_hash_h1(buf32, &ietf_frost_binding_factor_inputs[i * IETF_FROST_BINDING_FACTOR_INPUT_SIZE],
                        IETF_FROST_BINDING_FACTOR_INPUT_SIZE);

        result = memcmp(&ietf_frost_binding_factors[i * IETF_FROST_BINDING_FACTOR_SIZE],
                        buf32, IETF_FROST_BINDING_FACTOR_SIZE);
        CHECK(result == 0);
    }

    /* Round one: compute binding factors */
    /* Collect the signing commitments of signers participating to round two */
    for (j = 0; j < IETF_FROST_NUM_PARTICIPANTS; j++) {
        i = (int) ietf_frost_participants[j] - 1;
        memcpy(&signing_commitments[j], &(nonces[i]->commitments), sizeof(secp256k1_frost_nonce_commitment));
    }

    /* Compute binding factors */
    binding_factors.num_binding_factors = IETF_FROST_NUM_PARTICIPANTS;
    binding_factors.binding_factors = (secp256k1_scalar *) checked_malloc(&default_error_callback,
                                            IETF_FROST_NUM_PARTICIPANTS * sizeof(secp256k1_scalar));
    binding_factors.participant_indexes = (uint32_t *) checked_malloc(&default_error_callback,
                                    IETF_FROST_NUM_PARTICIPANTS * sizeof(uint32_t));
    result = compute_binding_factors(sign_ctx, &binding_factors, ietf_frost_message,
                                     ietf_frost_message_length, IETF_FROST_NUM_PARTICIPANTS,
                                     keypairs[0].public_keys.group_public_key, signing_commitments);
    CHECK(result == 1);

    /* Round two: verify the computed binding factors */
    for (j = 0; j < IETF_FROST_NUM_PARTICIPANTS; j++) {
        unsigned char buffer32[32];
        i = (int) binding_factors.participant_indexes[j] - 1;
        secp256k1_scalar_get_b32(buffer32, &binding_factors.binding_factors[j]);
        result = memcmp(&ietf_frost_binding_factors[i * IETF_FROST_BINDING_FACTOR_SIZE],
                        buffer32, IETF_FROST_BINDING_FACTOR_SIZE);
        CHECK(result == 0);
    }

    /* **** **** IETF Test Vector: Round Two **** **** */
    /* Round two: Sign */
    for (j = 0; j < IETF_FROST_NUM_PARTICIPANTS; j++) {
        i = (int) binding_factors.participant_indexes[j] - 1;
        result = secp256k1_frost_sign(sign_ctx, &signature_shares[j],
                             ietf_frost_message, ietf_frost_message_length,
                             IETF_FROST_NUM_PARTICIPANTS,&keypairs[i],
                             nonces[i], signing_commitments);
        CHECK(result == 1);
        result = memcmp(&ietf_frost_sig_shares[i * IETF_FROST_SIG_SHARE_SIZE],
                        signature_shares[j].response, IETF_FROST_SIG_SHARE_SIZE);
        CHECK(result == 0);
    }


    {
        secp256k1_frost_pubkey public_keys[IETF_FROST_NUM_PARTICIPANTS];
        unsigned char signature[65];
        /* Extracting public_keys from keypair. This operation is intended to be executed by each signer.  */
        for (index = 0; index < IETF_FROST_NUM_PARTICIPANTS; index++) {
            i = (int) signature_shares[index].index - 1;
            secp256k1_frost_pubkey_from_keypair(&public_keys[index], &keypairs[i]);
        }
        result = secp256k1_frost_aggregate(sign_ctx, signature, ietf_frost_message,
                                           ietf_frost_message_length,
                                          &keypairs[0],
                                          public_keys,
                                          signing_commitments, signature_shares,
                                          IETF_FROST_NUM_PARTICIPANTS);
        CHECK(result == 1);
        result = memcmp(ietf_frost_sig, signature, IETF_FROST_SIG_SIZE);
        CHECK(result == 0);

        /* Check: verify if the aggregate signature appears as correct */
        result = secp256k1_frost_verify(sign_ctx, signature, ietf_frost_message,
                               ietf_frost_message_length, &public_keys[0]);
        CHECK(result == 1);
    }

    /* Cleanup */
    for (index = 0; index < IETF_FROST_MAX_PARTICIPANTS; index++) {
        secp256k1_frost_nonce_destroy(nonces[index]);
    }
    free_binding_factors(&binding_factors);
    secp256k1_context_destroy(sign_ctx);

}

#endif /* SECP256K1_MODULE_FROST_TESTS_FROST_RFC9591_H */
