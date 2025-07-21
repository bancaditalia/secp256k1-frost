/***********************************************************************
 * Copyright (c) 2025 Bank of Italy                                    *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_FROST_TESTS_BIGINT_H
#define SECP256K1_MODULE_FROST_TESTS_BIGINT_H

/*
 * BEWARE:
 *    the following file is generated at compile time by a script in
 *    <BASE>/tools/frost_generate_bigint_test_vectors.py
 *
 *    It is not part of the repository.
 */
#include "vectors/bigint_test_vectors.h"

static void test_reduce_bigint_mod_p(void) {
    unsigned char result[32];
    int i;
    bigint_internal r;
    for (i = 0; i < bigint_mod_p_test_vector_total_tests; i++) {
        CHECK(bigint_mod(&r, test_case_inputs[i], &secp256k1_p_bigint) == 0);
        CHECK(bigint_to_bytes_be(result, &r) == 0);
        CHECK(memcmp(result, expected_outputs[i], 32) == 0);
    }
}

#endif /* SECP256K1_MODULE_FROST_TESTS_BIGINT_H */
