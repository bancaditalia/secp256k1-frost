/***********************************************************************
 * Copyright (c) 2025 Bank of Italy                                    *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_FROST_BENCH_H
#define SECP256K1_MODULE_FROST_BENCH_H

#include "../../../include/secp256k1_frost.h"
#include "fill_random.h"

#define BENCH_FROST_MSGLEN (32)
#define BENCH_FROST_MAX_PARTICIPANTS 3
#define BENCH_FROST_THR_PARTICIPANTS 2

typedef struct {
  secp256k1_frost_keypair *keypairs;
  secp256k1_frost_nonce **nonces;
  secp256k1_frost_nonce_commitment *signing_commitments;
  secp256k1_frost_pubkey *public_keys;
  secp256k1_frost_signature_share *signature_shares;
  unsigned char signature[FROST_SIGNATURE_SIZE];
} secp256k1_frost_data_per_iter;

typedef struct {
    secp256k1_context *ctx;
    int n;
    const unsigned char **msgs;
    secp256k1_frost_data_per_iter *state;
} bench_frost_data;

static void bench_frost_sign(void* arg, int iters) {
    bench_frost_data *data = (bench_frost_data *)arg;
    int i, j, signer_index;
    secp256k1_frost_signature_share signature_share;

    for (i = 0; i < iters; i++) {
        signer_index = i % BENCH_FROST_THR_PARTICIPANTS;

        /* TODO: FIXME - here the same experiment is run (count) times, and nonces are reused.
         * We do not want to generate new nonces, otherwise the signing time is compromised. */
        for (j = 0; j < BENCH_FROST_THR_PARTICIPANTS; j++) {
            data->state[i].nonces[j]->used = 0;
        }
        CHECK(secp256k1_frost_sign(data->ctx,
                                   &signature_share,
                                   data->msgs[i],
                                   BENCH_FROST_MSGLEN,
                                   BENCH_FROST_THR_PARTICIPANTS,
                                   &data->state[i].keypairs[signer_index],
                                   data->state[i].nonces[signer_index],
                                   data->state[i].signing_commitments) == 1);
    }
}

static void bench_frost_aggregate(void* arg, int iters) {
    bench_frost_data *data = (bench_frost_data *)arg;
    int i, signer_index;
    unsigned char signature[FROST_SIGNATURE_SIZE];

    for (i = 0; i < iters; i++) {
        signer_index = i % BENCH_FROST_THR_PARTICIPANTS;
        /* We aggregate 3 shares out of the 3 provided */
        CHECK(secp256k1_frost_aggregate(data->ctx,
                                        signature,
                                        data->msgs[i],
                                        BENCH_FROST_MSGLEN,
                                        &data->state[i].keypairs[signer_index],
                                        data->state[i].public_keys,
                                        data->state[i].signing_commitments,
                                        data->state[i].signature_shares,
                                        BENCH_FROST_THR_PARTICIPANTS) == 1);
    }
}

static void bench_frost_verify(void* arg, int iters) {
    bench_frost_data *data = (bench_frost_data *)arg;
    int i;

    for (i = 0; i < iters; i++) {
        CHECK(secp256k1_frost_verify(data->ctx,
                                     data->state[i].signature,
                                     data->msgs[i],
                                     BENCH_FROST_MSGLEN,
                                     data->state[i].public_keys) == 1);
    }
}

static void bench_frost_data_init(bench_frost_data *data, int iters) {
    int i, j;
    unsigned char hiding_seed[32], binding_seed[32];
    secp256k1_frost_vss_commitments *_dealer_commitments;
    secp256k1_frost_keygen_secret_share _shares_by_participant[BENCH_FROST_MAX_PARTICIPANTS];

    /* Allocate benchmark data */
    data->ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    data->state = (secp256k1_frost_data_per_iter *)malloc(iters * sizeof(secp256k1_frost_data_per_iter));
    data->msgs = (const unsigned char **)malloc(iters * sizeof(unsigned char *));

    /*
     * Prepare data for each iteration: at each iteration, we use different
     * key-pairs, nonces, and commitments. In this way, each iteration performs
     * equivalent (but not the same) operations.
     */
    for (i = 0; i < iters; i++) {
        unsigned char *msg = (unsigned char *)malloc(BENCH_FROST_MSGLEN);
        data->state[i].keypairs = (secp256k1_frost_keypair *) malloc(BENCH_FROST_MAX_PARTICIPANTS * sizeof(secp256k1_frost_keypair));
        data->state[i].nonces = (secp256k1_frost_nonce **)malloc(BENCH_FROST_THR_PARTICIPANTS * sizeof(secp256k1_frost_nonce*));
        data->state[i].signing_commitments = (secp256k1_frost_nonce_commitment *)malloc(BENCH_FROST_THR_PARTICIPANTS * sizeof(secp256k1_frost_nonce_commitment));
        data->state[i].public_keys = (secp256k1_frost_pubkey *)malloc(BENCH_FROST_THR_PARTICIPANTS * sizeof(secp256k1_frost_pubkey));
        data->state[i].signature_shares = (secp256k1_frost_signature_share *)malloc(BENCH_FROST_THR_PARTICIPANTS * sizeof(secp256k1_frost_signature_share));

        /* Message Generation */
        msg[0] = i; msg[1] = i >> 8; msg[2] = i >> 16; msg[3] = i >> 24;
        memset(&msg[4], 'm', BENCH_FROST_MSGLEN - 4);
        data->msgs[i] = msg;

        /* Key Generation */
        _dealer_commitments = secp256k1_frost_vss_commitments_create(BENCH_FROST_THR_PARTICIPANTS);
        CHECK(secp256k1_frost_keygen_with_dealer(data->ctx,
                                                 _dealer_commitments,
                                                 _shares_by_participant,
                                                 data->state[i].keypairs,
                                                 BENCH_FROST_MAX_PARTICIPANTS,
                                                 BENCH_FROST_THR_PARTICIPANTS) == 1);

        secp256k1_frost_vss_commitments_destroy(_dealer_commitments);

        /* Extracting public_keys from keypair. This operation is intended to be executed by each signer. */
        for (j = 0; j < BENCH_FROST_THR_PARTICIPANTS; j++) {
            secp256k1_frost_pubkey_from_keypair(&data->state[i].public_keys[j], &data->state[i].keypairs[j]);
        }

        /* Nonce and Commitment Generation */
        for (j = 0; j < BENCH_FROST_THR_PARTICIPANTS; j++) {
            fill_random(binding_seed, sizeof(binding_seed));
            fill_random(hiding_seed, sizeof(hiding_seed));
            data->state[i].nonces[j] = secp256k1_frost_nonce_create(data->ctx,
                                                                    &data->state[i].keypairs[j],
                                                                    binding_seed,
                                                                    hiding_seed);
            memcpy(&data->state[i].signing_commitments[j],
                   &(data->state[i].nonces[j]->commitments), sizeof(secp256k1_frost_nonce_commitment));
        }

        /* Prepare signature shares for aggregation benchmark */
        for (j = 0; j < BENCH_FROST_THR_PARTICIPANTS; j++) {
            CHECK(secp256k1_frost_sign(data->ctx,
                                       &data->state[i].signature_shares[j],
                                       data->msgs[i],
                                       BENCH_FROST_MSGLEN,
                                       BENCH_FROST_THR_PARTICIPANTS,
                                       &data->state[i].keypairs[j],
                                       data->state[i].nonces[j],
                                       data->state[i].signing_commitments) == 1);
        }
        for (j = 0; j < BENCH_FROST_THR_PARTICIPANTS; j++) {
            data->state[i].nonces[j]->used = 0;
        }

        /* Prepare aggregated signature for verification benchmark */
        CHECK(secp256k1_frost_aggregate(data->ctx,
                                        data->state[i].signature,
                                        data->msgs[i],
                                        BENCH_FROST_MSGLEN,
                                        &data->state[i].keypairs[0],
                                        data->state[i].public_keys,
                                        data->state[i].signing_commitments,
                                        data->state[i].signature_shares,
                                        BENCH_FROST_THR_PARTICIPANTS) == 1);
    }
}

static void bench_frost_data_cleanup(bench_frost_data *data, int iters) {
    int i, j;
    for (i = 0; i < iters; i++) {
        free((void *) (*data).msgs[i]);
        free((void *) (*data).state[i].keypairs);
        free((void *) (*data).state[i].signing_commitments);
        free((void *) (*data).state[i].public_keys);
        free((void *) (*data).state[i].signature_shares);
        for (j = 0; j < BENCH_FROST_THR_PARTICIPANTS;j++) {
            secp256k1_frost_nonce_destroy((*data).state[i].nonces[j]);
        }
        free((void *) (*data).state[i].nonces);
    }
    free((void *) (*data).msgs);
    free((void *) (*data).state);
    secp256k1_context_destroy((*data).ctx);
}

static void run_frost_bench(int iters, int argc, char** argv) {
    bench_frost_data data;
    int d = argc == 1;
    int runs = 10;
    char frost_aggregate_label[25];

    /* Initialize benchmark data */
    bench_frost_data_init(&data, iters);

    /* Run benchmarks */
    if (d || have_flag(argc, argv, "frost") || have_flag(argc, argv, "sign")
        || have_flag(argc, argv, "frost_sign")){
        run_benchmark("frost_sign", bench_frost_sign, NULL, NULL,
                      (void *) &data, runs, iters);
    }
    if (d || have_flag(argc, argv, "frost") || have_flag(argc, argv, "aggregate")
        || have_flag(argc, argv, "frost_aggregate")){
        sprintf(frost_aggregate_label, "frost_aggregate (%d/%d)",
                BENCH_FROST_THR_PARTICIPANTS, BENCH_FROST_MAX_PARTICIPANTS);
        run_benchmark(frost_aggregate_label,
                      bench_frost_aggregate, NULL, NULL,
                      (void *) &data, runs, iters);
    }
    if (d || have_flag(argc, argv, "frost") || have_flag(argc, argv, "verify")
        || have_flag(argc, argv, "frost_verify")){
        run_benchmark("frost_verify", bench_frost_verify, NULL, NULL,
                      (void *) &data, runs, iters);
    }

    /* Cleaning up data */
    bench_frost_data_cleanup(&data, iters);
}

#endif /* SECP256K1_MODULE_FROST_BENCH_H */
