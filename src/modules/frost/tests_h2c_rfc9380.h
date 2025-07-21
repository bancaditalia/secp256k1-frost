/***********************************************************************
 * Copyright (c) 2025 Bank of Italy                                    *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_FROST_TESTS_H2C_RFC9380_H
#define SECP256K1_MODULE_FROST_TESTS_H2C_RFC9380_H

#include "vectors/bigint_mod_p_test_vectors.h"
#include "vectors/ietf_h2c_iso3map_test_vectors.h"
#include "vectors/ietf_h2c_rfc9380_expander_test_vectors.h"
#include "vectors/ietf_h2c_rfc9380_test_vectors.h"
#include "vectors/ietf_h2c_sqrt_ratio_test_vectors.h"

/* ************ Test Vector for testing bigint_internal functionality ********** */
static void test_reduce_bigint_mod_p(void) {
    unsigned char result[32];
    int i;
    for (i = 0; i < bigint_mod_p_test_vector_total_tests; i++) {
        bigint_internal r;
        bigint_mod(&r, bigint_mod_p_test_vector_inputs[i], &secp256k1_p_bigint);
        CHECK(bigint_to_bytes_be(result, &r) == 0);
        CHECK(memcmp(result, bigint_mod_p_test_vector_outputs[i], 32) == 0);
    }
}

/* ******* Supplemental functions to check OS2IP and I2OSP ******* */
static int i2osp_bigint(uint8_t *out, size_t len, const bigint_internal *x) {
    size_t i;
    size_t length_in_bits = x->nlimbs * 64;
    if (length_in_bits > len * 8) {
        return 0; /* x too large to encode in `len` bytes */
    }

    memset(out, 0, len);
    for (i = 0; i < len; i++) {
        size_t bit_index = (len - 1 - i) * 8;
        size_t limb = bit_index / 64;
        size_t shift = bit_index % 64;
        if (limb < x->nlimbs) {
            out[i] = (x->limbs[limb] >> shift) & 0xFF;
        }
    }
    return 1;
}

/* ******* Test primitives against test vectors ******* */
void test_h2c_OS2IP(void) {
    int ok;
    uint8_t m2[16];
    uint8_t m1[16] = {
        0x00, 0x01, 0x23, 0x45,
        0x67, 0x89, 0xab, 0xcd,
        0xef, 0x00, 0x11, 0x22,
        0x33, 0x44, 0x55, 0x66
    };

    bigint_internal x;
    OS2IP(&x, m1, 16);
    ok = i2osp_bigint(m2, 16, &x);
    CHECK(ok);

    CHECK(memcmp(m1, m2, 16) == 0);
}

void test_h2c_I2OSP(void) {
    int ok;
    /* We should use an array of at least 8 uint8_t, because bigint_internal internally represent
     * integers using arrays of uint64_t (8 bytes), whereas uint8_t is 1 byte. */
    uint8_t out2[8];
    unsigned char out1[8];
    bigint_internal x;

    /* A random number */
    uint32_t input = 0xb16dc83d;

    I2OSP(out1, input, 8);

    x.limbs[0] = input;
    x.nlimbs = 1;
    ok = i2osp_bigint(out2, 8, &x);
    CHECK(ok);

    CHECK(memcmp(out1, out2, sizeof(uint8_t)) == 0);
}

/* Test vector for sqrt_ration generated with:
 *  tools/test_vectors_h2c_sqrt_ratio_generate.py              */
void test_h2c_sqrt_ratio(void) {
    unsigned long i;
    for (i = 0; i < IETF_H2C_SQRT_RATIO_NUM_TEST_VECTORS; i++) {
        secp256k1_fe u, v, y, expected_y;
        int is_qr;

        secp256k1_fe_set_b32_mod(&u, sqrt_ratio_vectors[i].u);
        secp256k1_fe_set_b32_mod(&v, sqrt_ratio_vectors[i].v);
        secp256k1_fe_set_b32_mod(&expected_y, sqrt_ratio_vectors[i].y);

        is_qr = sqrt_ratio(&y, &u, &v);
        CHECK(is_qr == sqrt_ratio_vectors[i].is_qr);

        secp256k1_fe_normalize(&y);
        secp256k1_fe_normalize(&expected_y);
        CHECK(secp256k1_fe_equal(&y, &expected_y));
    }
}

/* Test vector for sqrt_ration generated with:
 *  tools/test_vectors_h2c_isomap_generate.py              */
void test_h2c_3isogeny_mapping_vectors(void) {
    size_t i;
    for (i = 0; i < IETF_H2C_ISO3MAP_NUM_TEST_VECTORS; i++) {
        secp256k1_ge Q_prime, Q;
        secp256k1_fe exp_x, exp_y;

        secp256k1_fe_set_b32_mod(&Q_prime.x, iso3_test_vectors[i].xp);
        secp256k1_fe_set_b32_mod(&Q_prime.y, iso3_test_vectors[i].yp);
        Q_prime.infinity = 0;

        /* Compute 3-isogeny map: (x, y) = iso_map(xp, yp) */
        iso_map(&Q, &Q_prime);

        secp256k1_fe_normalize(&Q.x);
        secp256k1_fe_normalize(&Q.y);

        secp256k1_fe_set_b32_mod(&exp_x, iso3_test_vectors[i].x);
        secp256k1_fe_set_b32_mod(&exp_y, iso3_test_vectors[i].y);

        secp256k1_fe_normalize(&exp_x);
        secp256k1_fe_normalize(&exp_y);

        CHECK(secp256k1_fe_equal(&Q.x, &exp_x));
        CHECK(secp256k1_fe_equal(&Q.y, &exp_y));
    }
}

/* Test expand_message_xmd against the RFC9380 test vector */
void test_h2c_rfc9380_expand_message_xmd(void) {
    int i;
    for (i = 0; i < IETF_RFC9380_EXP_TEST_VECTORS; i++) {
        int result;
        uint32_t len_in_bytes, dst_length;
        unsigned char *dst_, *uniform_bytes, *dst_prime, *msg_prime;
        const ietf_rfc9380_expander_test_vector *tv;

        tv = &ietf_rfc9380_expander_test_vectors[i];
        len_in_bytes = tv->len_in_bytes;
        dst_length = IETF_RFC9380_EXP_DST_LEN;

        /* Individually test dst expansion */
        dst_ = reduce_dst_if_needed_xmd(ietf_rfc9380_exp_dst, &dst_length);
        dst_prime = (unsigned char *) checked_malloc(&default_error_callback, dst_length + 1);
        compute_dst_prime(dst_prime, dst_, dst_length);
        result = memcmp(dst_prime, ietf_rfc9380_exp_dst_prime, IETF_RFC9380_EXP_DST_PRIME_LEN);
        /* check if they are equal */
        CHECK(result == 0);

        /* Individually test msg expansion */
        msg_prime = (unsigned char *) checked_malloc(&default_error_callback,
                                                     IETF_RFC9380_SHA256_S_IN_BYTES
                                                     + tv->msg_len + 2
                                                     + 1 + dst_length + 1);
        compute_msg_prime(msg_prime, &ietf_rfc9380_exp_msgs[tv->msg_offset], tv->msg_len,
                          dst_prime, dst_length, len_in_bytes);
        result = memcmp(msg_prime, &ietf_rfc9380_exp_msg_primes[tv->msg_prime_offset], tv->msg_prime_len);
        /* check if they are equal */
        CHECK(result == 0);
        free(dst_);
        free(dst_prime);
        free(msg_prime);

        /* Test generation of uniform bytes */
        uniform_bytes = (unsigned char *) checked_malloc(&default_error_callback,
                                                         len_in_bytes);
        result = expand_message_xmd(uniform_bytes, &ietf_rfc9380_exp_msgs[tv->msg_offset], tv->msg_len,
                                    ietf_rfc9380_exp_dst, IETF_RFC9380_EXP_DST_LEN,
                                    len_in_bytes);
        /* expand_message_xmd outputs 1 on success */
        CHECK(result == 1);
        result = memcmp(uniform_bytes, &ietf_rfc9380_exp_uniform_bytes[tv->uniform_bytes_offset], len_in_bytes);
        /* check if they are equal */
        CHECK(result == 0);
        free(uniform_bytes);
    }
}

/* Test hash_to_curve against the RFC9380 test vector */
void test_h2c_rfc9380_hash_to_curve_test_vectors(void) {
    int i;
    secp256k1_gej P;

    for (i = 0; i < IETF_RFC9380_RO_TEST_VECTORS; i++) {
        secp256k1_fe u[2];
        secp256k1_gej Q[2];
        const ietf_rfc9380_test_vector *tv;
        unsigned char buffer[32];
        int result;
        tv = &ietf_rfc9380_ro_test_vectors[i];

        hash_to_field(u,
                      &ietf_rfc9380_ro_messages[tv->msg_offset], tv->msg_len,
                      ietf_rfc9380_ro_dst,
                      IETF_RFC9380_RO_DST_LEN, 2);

        secp256k1_fe_normalize_var(&u[0]);
        secp256k1_fe_get_b32(buffer, &u[0]);
        result = memcmp(&ietf_rfc9380_ro_u0s[i * IETF_RFC9380_RO_u0_SIZE], buffer, IETF_RFC9380_RO_u0_SIZE);

        CHECK(result == 0);
        secp256k1_fe_normalize_var(&u[1]);
        secp256k1_fe_get_b32(buffer, &u[1]);
        result = memcmp(&ietf_rfc9380_ro_u1s[i * IETF_RFC9380_RO_u1_SIZE], buffer, IETF_RFC9380_RO_u1_SIZE);
        CHECK(result == 0);

        map_to_curve(&Q[0], &u[0]);
        map_to_curve(&Q[1], &u[1]);
        {
            /* Compare Q[0] and Q[1] against those in the test vectors */
            secp256k1_ge q0, q1;
            secp256k1_ge_set_gej_var(&q0, &Q[0]);
            secp256k1_ge_set_gej_var(&q1, &Q[1]);

            secp256k1_fe_normalize_var(&q0.x);
            secp256k1_fe_get_b32(buffer, &q0.x);
            result = memcmp(&ietf_rfc9380_ro_q0xs[i * IETF_RFC9380_RO_Q0x_SIZE], buffer, IETF_RFC9380_RO_Q0x_SIZE);
            CHECK(result == 0);
            secp256k1_fe_normalize_var(&q0.y);
            secp256k1_fe_get_b32(buffer, &q0.y);
            result = memcmp(&ietf_rfc9380_ro_q0ys[i * IETF_RFC9380_RO_Q0y_SIZE], buffer, IETF_RFC9380_RO_Q0y_SIZE);
            CHECK(result == 0);

            secp256k1_fe_normalize_var(&q1.x);
            secp256k1_fe_get_b32(buffer, &q1.x);
            result = memcmp(&ietf_rfc9380_ro_q1xs[i * IETF_RFC9380_RO_Q1x_SIZE], buffer, IETF_RFC9380_RO_Q1x_SIZE);
            CHECK(result == 0);
            secp256k1_fe_normalize_var(&q1.y);
            secp256k1_fe_get_b32(buffer, &q1.y);
            result = memcmp(&ietf_rfc9380_ro_q1ys[i * IETF_RFC9380_RO_Q1y_SIZE], buffer, IETF_RFC9380_RO_Q1y_SIZE);
            CHECK(result == 0);

        }
        secp256k1_gej_add_var(&P, &Q[0], &Q[1], NULL);
        clear_cofactor(&P);
        {
            /* Compare P against the test vector */
            secp256k1_ge P_ge;
            secp256k1_ge_set_gej_var(&P_ge, &P);

            secp256k1_fe_normalize_var(&P_ge.x);
            secp256k1_fe_get_b32(buffer, &P_ge.x);
            result = memcmp(&ietf_rfc9380_ro_pxs[i * IETF_RFC9380_RO_Px_SIZE], buffer, IETF_RFC9380_RO_Px_SIZE);
            CHECK(result == 0);

            secp256k1_fe_normalize_var(&P_ge.y);
            secp256k1_fe_get_b32(buffer, &P_ge.y);
            result = memcmp(&ietf_rfc9380_ro_pys[i * IETF_RFC9380_RO_Py_SIZE], buffer, IETF_RFC9380_RO_Py_SIZE);
            CHECK(result == 0);

            secp256k1_ge_clear(&P_ge);
        }
    }
}

void test_h2c_rfc9380_hash_to_curve_e2e_test_vectors(void) {
    int i;
    secp256k1_gej P;

    for (i = 1; i < IETF_RFC9380_RO_TEST_VECTORS; i++) {
        const ietf_rfc9380_test_vector *tv;
        int result;
        tv = &ietf_rfc9380_ro_test_vectors[i];

        hash_to_curve(&P,
                      &ietf_rfc9380_ro_messages[tv->msg_offset], tv->msg_len,
                      ietf_rfc9380_ro_dst,
                      IETF_RFC9380_RO_DST_LEN);

        {
            /* Compare P against the test vector */
            secp256k1_ge P_ge;
            unsigned char buffer[32];
            secp256k1_ge_set_gej_var(&P_ge, &P);

            secp256k1_fe_normalize_var(&P_ge.x);
            secp256k1_fe_get_b32(buffer, &P_ge.x);
            result = memcmp(&ietf_rfc9380_ro_pxs[i * IETF_RFC9380_RO_Px_SIZE], buffer, IETF_RFC9380_RO_Px_SIZE);
            CHECK(result == 0);

            secp256k1_fe_normalize_var(&P_ge.y);
            secp256k1_fe_get_b32(buffer, &P_ge.y);
            result = memcmp(&ietf_rfc9380_ro_pys[i * IETF_RFC9380_RO_Py_SIZE], buffer, IETF_RFC9380_RO_Py_SIZE);
            CHECK(result == 0);

            secp256k1_ge_clear(&P_ge);
        }
    }

    secp256k1_gej_clear(&P);
}

/* Test encode_to_curve against the RFC9380 test vector */
void test_h2c_rfc9380_encode_to_curve_test_vectors(void) {
    int i;

    for (i = 1; i < IETF_RFC9380_NU_TEST_VECTORS; i++) {
        secp256k1_fe u;
        secp256k1_gej Q;
        const ietf_rfc9380_test_vector *tv;
        unsigned char buffer[32];
        int result;
        tv = &ietf_rfc9380_nu_test_vectors[i];

        hash_to_field(&u,
                      &ietf_rfc9380_nu_messages[tv->msg_offset], tv->msg_len,
                      ietf_rfc9380_nu_dst,
                      IETF_RFC9380_NU_DST_LEN, 1);

        secp256k1_fe_normalize_var(&u);
        secp256k1_fe_get_b32(buffer, &u);
        result = memcmp(&ietf_rfc9380_nu_u0s[i * IETF_RFC9380_NU_u0_SIZE], buffer, IETF_RFC9380_NU_u0_SIZE);

        CHECK(result == 0);
        map_to_curve(&Q, &u);
        {
            /* Compare Q against the test vectors */
            secp256k1_ge q0;
            secp256k1_ge_set_gej_var(&q0, &Q);

            secp256k1_fe_normalize_var(&q0.x);
            secp256k1_fe_get_b32(buffer, &q0.x);
            result = memcmp(&ietf_rfc9380_nu_qxs[i * IETF_RFC9380_NU_Qx_SIZE], buffer, IETF_RFC9380_NU_Qx_SIZE);
            CHECK(result == 0);
            secp256k1_fe_normalize_var(&q0.y);
            secp256k1_fe_get_b32(buffer, &q0.y);
            result = memcmp(&ietf_rfc9380_nu_qys[i * IETF_RFC9380_NU_Qy_SIZE], buffer, IETF_RFC9380_NU_Qy_SIZE);
            CHECK(result == 0);
        }

        clear_cofactor(&Q);
        {
            /* Compare P against the test vector */
            secp256k1_ge P_ge;
            secp256k1_ge_set_gej_var(&P_ge, &Q);

            secp256k1_fe_normalize_var(&P_ge.x);
            secp256k1_fe_get_b32(buffer, &P_ge.x);
            result = memcmp(&ietf_rfc9380_nu_pxs[i * IETF_RFC9380_NU_Px_SIZE], buffer, IETF_RFC9380_NU_Px_SIZE);
            CHECK(result == 0);

            secp256k1_fe_normalize_var(&P_ge.y);
            secp256k1_fe_get_b32(buffer, &P_ge.y);
            result = memcmp(&ietf_rfc9380_nu_pys[i * IETF_RFC9380_NU_Py_SIZE], buffer, IETF_RFC9380_NU_Py_SIZE);
            CHECK(result == 0);

            secp256k1_ge_clear(&P_ge);
        }
    }
}

void test_h2c_rfc9380_encode_to_curve_e2e_test_vectors(void) {
    int i;
    secp256k1_gej P;

    for (i = 1; i < IETF_RFC9380_NU_TEST_VECTORS; i++) {
        const ietf_rfc9380_test_vector *tv;
        int result;
        tv = &ietf_rfc9380_nu_test_vectors[i];

        encode_to_curve(&P,
                        &ietf_rfc9380_nu_messages[tv->msg_offset], tv->msg_len,
                        ietf_rfc9380_nu_dst,
                        IETF_RFC9380_NU_DST_LEN);

        {
            /* Compare P against the test vector */
            secp256k1_ge P_ge;
            unsigned char buffer[32];
            secp256k1_ge_set_gej_var(&P_ge, &P);

            secp256k1_fe_normalize_var(&P_ge.x);
            secp256k1_fe_get_b32(buffer, &P_ge.x);
            result = memcmp(&ietf_rfc9380_nu_pxs[i * IETF_RFC9380_NU_Px_SIZE], buffer, IETF_RFC9380_NU_Px_SIZE);
            CHECK(result == 0);

            secp256k1_fe_normalize_var(&P_ge.y);
            secp256k1_fe_get_b32(buffer, &P_ge.y);
            result = memcmp(&ietf_rfc9380_nu_pys[i * IETF_RFC9380_NU_Py_SIZE], buffer, IETF_RFC9380_NU_Py_SIZE);
            CHECK(result == 0);

            secp256k1_ge_clear(&P_ge);
        }
    }

    secp256k1_gej_clear(&P);
}

#endif /* SECP256K1_MODULE_FROST_TESTS_H2C_RFC9380_H */
