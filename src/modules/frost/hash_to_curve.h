#ifndef LIBSECP256K1_HASH_TO_CURVE_H
#define LIBSECP256K1_HASH_TO_CURVE_H

#include "../../../include/secp256k1.h"
#include "../../../include/secp256k1_frost.h"
#include <assert.h>
/*
 * The function hash_to_field hashes arbitrary-length byte strings to
 * a list of one or more elements of a finite field F;
 *
 * Inputs:
 * - msg, a byte string containing the message to hash.
 * - count, the number of elements of F to output.
 * Outputs:
 * - (u_0, ..., u_(count - 1)), a list of field elements.
 */
#define IETF_RFC9380_SECP256K1_p (2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1)
#define IETF_RFC9380_SECP256K1_m (1U)
#define IETF_RFC9380_SECP256K1_k (128U)
#define IETF_RFC9380_SECP256K1_L (48U)
#define IETF_RFC9380_SECP256K1_Z (-11)
#define IETF_RFC9380_SHA256_B_IN_BYTES (32U)
#define IETF_RFC9380_SHA256_S_IN_BYTES (64U)

/*
 * Integer to Octet String Primitive (I2OSP)
 * https://datatracker.ietf.org/doc/html/rfc8017#section-4.1
 */
static void I2OSP(unsigned char* output, uint32_t x, uint32_t output_length){
    int i;
    for (i = (int) output_length - 1; i >= 0; --i) {
        output[i] = (unsigned char) (x & 0xFF);
        x >>= 8;
    }
}

/*
 * Octet String to Integer Primitive (OS2IP)
 * https://datatracker.ietf.org/doc/html/rfc8017#section-4.2
 */
static void OS2IP(uint32_t *output, const unsigned char* x, uint32_t length){
    int i;
    for (i = 0; i < (int) length; ++i) {
        *output = (*output) << 8 | x[i];
    }
}

/*
 * xor_strings - XOR two strings together to produce a third string
 *  dest[0,..,n-1] := src_a[0,..,n-1] ^ src_b[0,..,n-1]
 */
static void strxor(unsigned char *dest, const unsigned char *src_a, const unsigned char *src_b, size_t n) {
    size_t i;

    /* assert no pointer overflow */
    assert(src_a + n > src_a);
    assert(src_b + n > src_b);
    assert(dest + n > dest);

    for (i = 0; i < n; i++) {
        dest[i] = src_a[i] ^ src_b[i];
    }
}

/* The expand_message_xmd function produces a uniformly random byte string using
 * the cryptographic hash function SHA256 that outputs 256 bits.
 *  Returns 1 on success, 0 on failure.
 *  Out:      output: array of uniform bytes. It should point to an allocated array of size len_in_bytes
 *  In:          msg: a byte string
 *        msg_length: length of msg
 *               dst: a domain separation tag (of at most 255 bytes)
 *        dst_length: actual length of dst
 *   length_in_bytes: length of the uniform byte array to produce in output
 */
static int expand_message_xmd(unsigned char *output,
                              const unsigned char *msg, uint32_t msg_length,
                              const unsigned char *dst, uint32_t dst_length,
                              uint32_t len_in_bytes) {
    uint32_t ell;
    unsigned char *dst_prime, *msg_prime, *uniform_bytes;
    unsigned char hash_value[SHA256_SIZE];
    unsigned char index2os[1];
    secp256k1_sha256 sha;
    unsigned char **b;
    uint32_t i, j;

    /* 1.  ell = ceil(len_in_bytes / b_in_bytes) */
    ell = 1 + (len_in_bytes - 1) / IETF_RFC9380_SHA256_B_IN_BYTES;
    /* 2.  ABORT if ell > 255 or len_in_bytes > 65535 or len(DST) > 255 */
    if (ell > 255 || len_in_bytes > 65535 || dst_length > 255) {
        /* ABORT */
        return 0;
    }

    /* 3.  DST_prime = DST || I2OSP(len(DST), 1) */
    dst_prime = (unsigned char *) checked_malloc(&default_error_callback, dst_length + 1);
    memcpy(&dst_prime[0], dst,dst_length);
    I2OSP(&dst_prime[dst_length], dst_length, 1);

    /* msg_prime_length = s_in_bytes + msg_length + 2 + 1 + dst_prime_length */
    msg_prime = (unsigned char *) checked_malloc(&default_error_callback,
                                                 IETF_RFC9380_SHA256_S_IN_BYTES + msg_length + 2 + 1 + dst_length + 1);

    /* 4.  Z_pad = I2OSP(0, s_in_bytes) */
    I2OSP(&msg_prime[0], 0, IETF_RFC9380_SHA256_S_IN_BYTES);

    /* Adding msg to msg_prime (Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime) */
    memcpy(&msg_prime[IETF_RFC9380_SHA256_S_IN_BYTES], msg,msg_length);

    /* 5.  l_i_b_str = I2OSP(len_in_bytes, 2) */
    /* 6.  msg_prime = Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime */
    I2OSP(&msg_prime[IETF_RFC9380_SHA256_S_IN_BYTES + msg_length], len_in_bytes, 2);
    I2OSP(&msg_prime[IETF_RFC9380_SHA256_S_IN_BYTES + msg_length + 2], 0, 1);
    memcpy(&msg_prime[IETF_RFC9380_SHA256_S_IN_BYTES + msg_length + 2 + 1], dst_prime,dst_length + 1);

    /* Allocating b_0, ...,  = H(msg_prime)  */
    b = malloc(ell * sizeof b);
    for (i = 0; i < ell; i++) {
        b[i] = malloc(SHA256_SIZE * sizeof *b);
    }

    /* 7.  b_0 = H(msg_prime) */
    secp256k1_sha256_initialize(&sha);
    secp256k1_sha256_write(&sha, msg_prime, IETF_RFC9380_SHA256_S_IN_BYTES + msg_length + 2 + 1 + dst_length + 1);
    secp256k1_sha256_finalize(&sha, b[0]);

    /* 8.  b_1 = H(b_0 || I2OSP(1, 1) || DST_prime) */
    secp256k1_sha256_initialize(&sha);
    secp256k1_sha256_write(&sha, b[0], SHA256_SIZE);
    I2OSP(index2os, 1, 1);
    secp256k1_sha256_write(&sha, index2os, 1);
    secp256k1_sha256_write(&sha, dst_prime, dst_length + 1);
    secp256k1_sha256_finalize(&sha, b[1]);

    /* TODO: ell is included?? */
    /* 9.  for i in (2, ..., ell):
     * 10.    b_i = H(strxor(b_0, b_(i - 1)) || I2OSP(i, 1) || DST_prime) */
    for (i = 2; i < ell; i++) {
        secp256k1_sha256_initialize(&sha);
        strxor(b[i], b[0], b[i - 1], SHA256_SIZE);
        secp256k1_sha256_write(&sha, b[i], SHA256_SIZE);
        I2OSP(index2os, i, 1);
        secp256k1_sha256_write(&sha, index2os, 1);
        secp256k1_sha256_write(&sha, dst_prime, dst_length + 1);
        secp256k1_sha256_finalize(&sha, b[i]);
    }

    /* 11. uniform_bytes = b_1 || ... || b_ell */
    uniform_bytes = (unsigned char *) checked_malloc(&default_error_callback, (ell - 1) * SHA256_SIZE);
    for (i = 1; i < ell; i++) {
        memcpy(&uniform_bytes[(i - 1) * SHA256_SIZE], b[i], SHA256_SIZE);
    }

    /* 12. return substr(uniform_bytes, 0, len_in_bytes) */
    memcpy(output, uniform_bytes, len_in_bytes);

    /* cleaning out dynamically allocated memory */
    if (dst_prime != NULL) {
        free(dst_prime);
    }
    if (msg_prime != NULL) {
        free(msg_prime);
    }
    if (uniform_bytes != NULL) {
        free(uniform_bytes);
    }
    for (i = 0; i < ell; i++) {
        free(b[i]);
    }
    free(b);

    return 1;
}

/*
 * The hash_to_field function hashes a byte string msg of arbitrary length into one
 * or more elements of a field F.
 *
 * This function works in two steps: it first hashes the input byte string to produce
 * a uniformly random byte string, and then interprets this byte string as one or more
 * elements of F.
 *
 * Out:    field_elems : pointer to an (allocated) array of field elements
 *  In:          msg: a byte string
 *        msg_length: length of msg
 *               dst: a domain separation tag (of at most 255 bytes)
 *        dst_length: actual length of dst
 *             count: length of the uniform byte array to produce in output
 */
static void hash_to_field(secp256k1_fe *field_elems,
                          const unsigned char *msg, uint32_t msg_length,
                          const unsigned char *dst, uint32_t dst_length,
                          uint32_t count) {

    uint32_t len_in_bytes, i, j, elm_offset;
    uint32_t e[IETF_RFC9380_SECP256K1_m];
    unsigned char *uniform_bytes;
    int emx_result;

    /* 1. len_in_bytes = count * m * L */
    len_in_bytes = count * IETF_RFC9380_SECP256K1_m * IETF_RFC9380_SECP256K1_L;

    /* 2. uniform_bytes = expand_message(msg, DST, len_in_bytes) */
    uniform_bytes = (unsigned char *) checked_malloc(&default_error_callback,
                                                     len_in_bytes);
    emx_result = expand_message_xmd(uniform_bytes, msg, msg_length, dst, dst_length, len_in_bytes);

    /* 3. for i in (0, ..., count - 1): */
    for (i = 0; i < count; i++){
        /* 4.   for j in (0, ..., m - 1): */
        for (j = 0; j < IETF_RFC9380_SECP256K1_m; j++) {
            /* 5.     elm_offset = L * (j + i * m) */
            elm_offset = IETF_RFC9380_SECP256K1_L * (j + i * IETF_RFC9380_SECP256K1_m);

            /* 6.     tv = substr(uniform_bytes, elm_offset, L) */
            /* 7.     e_j = OS2IP(tv) mod p */
            OS2IP(&e[j], &uniform_bytes[elm_offset], IETF_RFC9380_SECP256K1_L);
            e[j] = e[j] % IETF_RFC9380_SECP256K1_p;
        }
        /* 8.   u_i = (e_0, ..., e_(m - 1)) */
        /* TODO: generalize this; here, we consider the specific case of m = 1 (as it is for secp256k1) */
        if (emx_result == 1) {
            secp256k1_fe_set_int(&field_elems[i], (int) e[0]);
        } else {
            secp256k1_fe_set_int(&field_elems[i], 0);
        }
    }

    if (uniform_bytes != NULL) {
        free(uniform_bytes);
    }

    /*  return (u_0, ..., u_(count - 1)) */
}

/* The function map_to_curve calculates a point on the elliptic curve E from
 * an element of the finite field F over which E is defined.
 *
 * For secp256k1, RFC9380 requires using the Simplified Shallue-van de Woestijne-Ulas
 * (SWU) method for AB == 0 (Section 6.6.3).
 * https://datatracker.ietf.org/doc/html/rfc9380#name-simplified-swu-for-ab-0
 */
static void map_to_curve(
        /*out: */ secp256k1_gej Q,
        /*in: */ secp256k1_fe *u,
        unsigned char *msg, uint32_t msg_length, uint32_t count) {
    /*
     *  1. (x', y') = map_to_curve_simple_swu(u)    # (x', y') is on E'
     *  2.   (x, y) = iso_map(x', y')               # (x, y) is on E
     *  3. return (x, y)
     */

}

/*
 * clear_cofactor(P) takes as input any point on the curve
 * and produces as output a point in the prime-order (sub)group G.
 *
 * The cofactor can always be cleared via scalar multiplication by h.
 *    clear_cofactor(P) := h_eff * P
 * For elliptic curves where h = 1, i.e., the curves with a prime number
 * of points, no operation is required.
 * For secp256k1, h_eff: 1
 */
static void clear_cofactor(/*in,out: */ secp256k1_gej* P) {
    /* Nothing to do for secp256k1 */
    P = P;
}


/*
 *  hash_to_curve is a uniform encoding from byte strings to points in G.
 *  That is, the distribution of its output is statistically close to uniform in G.
 *
 */
static int hash_to_curve(
        /*out: */
        /*in: */ const unsigned char *msg, uint32_t msg_length,
                 const unsigned char *dst, uint32_t dst_length) {

    secp256k1_gej point;
    /*
     * Input: msg, an arbitrary-length byte string.
     * Output: P, a point in G.
     * Steps:
     *  1. u = hash_to_field(msg, 2)
     *  2. Q0 = map_to_curve(u[0])
     *  3. Q1 = map_to_curve(u[1])
     *  4. R = Q0 + Q1              # Point addition
     *  5. P = clear_cofactor(R)
     *  6. return P
     */

    secp256k1_fe u[2];
    secp256k1_gej Q[2];

    hash_to_field(u, msg, msg_length, dst, dst_length, 2);

    clear_cofactor(&point);

    return 1;
}

#endif /* LIBSECP256K1_HASH_TO_CURVE_H */
