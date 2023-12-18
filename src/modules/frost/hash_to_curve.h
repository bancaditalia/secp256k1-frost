#ifndef LIBSECP256K1_HASH_TO_CURVE_H
#define LIBSECP256K1_HASH_TO_CURVE_H

#include "../../../include/secp256k1.h"
#include "../../../include/secp256k1_frost.h"
#include <assert.h>

/* p = 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1
 * it is the default p parameter of the secp256k1 elliptic curve */
#define IETF_RFC9380_SECP256K1_m (1U)
/* #define IETF_RFC9380_SECP256K1_k (128U) */
#define IETF_RFC9380_SECP256K1_L (48U)
#define IETF_RFC9380_SECP256K1_Z (-11)
#define IETF_RFC9380_SHA256_B_IN_BYTES (32U)
#define IETF_RFC9380_SHA256_S_IN_BYTES (64U)
#define IETF_RFC9380_M2C_B (1771U)

static const unsigned char ietf_rfc9380_m2c_a_prime[] = {
        0x3f, 0x87, 0x31, 0xab, 0xdd, 0x66, 0x1a, 0xdc, 0xa0, 0x8a,
        0x55, 0x58, 0xf0, 0xf5, 0xd2, 0x72, 0xe9, 0x53, 0xd3, 0x63,
        0xcb, 0x6f, 0x0e, 0x5d, 0x40, 0x54, 0x47, 0xc0, 0x1a, 0x44,
        0x45, 0x33};
static const unsigned char ietf_rfc9380_3isogeny_map_secp256k1_k_1_0[] = {
        0x8e, 0x38, 0xe3, 0x8e, 0x38, 0xe3, 0x8e, 0x38, 0xe3, 0x8e,
        0x38, 0xe3, 0x8e, 0x38, 0xe3, 0x8e, 0x38, 0xe3, 0x8e, 0x38,
        0xe3, 0x8e, 0x38, 0xe3, 0x8e, 0x38, 0xe3, 0x8d, 0xaa, 0xaa,
        0xa8, 0xc7
};
static const unsigned char ietf_rfc9380_3isogeny_map_secp256k1_k_1_1[] = {
        0x7, 0xd3, 0xd4, 0xc8, 0x0b, 0xc3, 0x21, 0xd5, 0xb9, 0xf3,
        0x15, 0xce, 0xa7, 0xfd, 0x44, 0xc5, 0xd5, 0x95, 0xd2, 0xfc,
        0x0b, 0xf6, 0x3b, 0x92, 0xdf, 0xff, 0x10, 0x44, 0xf1, 0x7c,
        0x65, 0x81
};
static const unsigned char ietf_rfc9380_3isogeny_map_secp256k1_k_1_2[] = {
        0x53, 0x4c, 0x32, 0x8d, 0x23, 0xf2, 0x34, 0xe6, 0xe2, 0xa4, 0x13,
        0xde, 0xca, 0x25, 0xca, 0xec, 0xe4, 0x50, 0x61, 0x44, 0x03,
        0x7c, 0x40, 0x31, 0x4e, 0xcb, 0xd0, 0xb5, 0x3d, 0x9d,
        0xd2, 0x62
};
static const unsigned char ietf_rfc9380_3isogeny_map_secp256k1_k_1_3[] = {
        0x8e, 0x38, 0xe3, 0x8e, 0x38, 0xe3, 0x8e, 0x38, 0xe3, 0x8e,
        0x38, 0xe3, 0x8e, 0x38, 0xe3, 0x8e, 0x38, 0xe3, 0x8e, 0x38,
        0xe3, 0x8e, 0x38, 0xe3, 0x8e, 0x38, 0xe3, 0x8d, 0xaa, 0xaa,
        0xa8, 0x8c
};
static const unsigned char ietf_rfc9380_3isogeny_map_secp256k1_k_2_0[] = {
        0xd3, 0x57, 0x71, 0x19, 0x3d, 0x94, 0x91, 0x8a, 0x9c, 0xa3,
        0x4c, 0xcb, 0xb7, 0xb6, 0x40, 0xdd, 0x86, 0xcd, 0x40, 0x95,
        0x42, 0xf8, 0x48, 0x7d, 0x9f, 0xe6, 0xb7, 0x45, 0x78, 0x1e,
        0xb4, 0x9b
};
static const unsigned char ietf_rfc9380_3isogeny_map_secp256k1_k_2_1[] = {
        0xed, 0xad, 0xc6, 0xf6, 0x43, 0x83, 0xdc, 0x1d, 0xf7, 0xc4,
        0xb2, 0xd5, 0x1b, 0x54, 0x22, 0x54, 0x06, 0xd3, 0x6b, 0x64,
        0x1f, 0x5e, 0x41, 0xbb, 0xc5, 0x2a, 0x56, 0x61, 0x2a, 0x8c,
        0x6d, 0x14
};
static const unsigned char ietf_rfc9380_3isogeny_map_secp256k1_k_3_0[] = {
        0x4b, 0xda, 0x12, 0xf6, 0x84, 0xbd, 0xa1, 0x2f, 0x68, 0x4b,
        0xda, 0x12, 0xf6, 0x84, 0xbd, 0xa1, 0x2f, 0x68, 0x4b, 0xda,
        0x12, 0xf6, 0x84, 0xbd, 0xa1, 0x2f, 0x68, 0x4b, 0x8e, 0x38,
        0xe2, 0x3c
};
static const unsigned char ietf_rfc9380_3isogeny_map_secp256k1_k_3_1[] = {
        0xc7, 0x5e, 0x0c, 0x32, 0xd5, 0xcb, 0x7c, 0x0f, 0xa9, 0xd0,
        0xa5, 0x4b, 0x12, 0xa0, 0xa6, 0xd5, 0x64, 0x7a, 0xb0, 0x46,
        0xd6, 0x86, 0xda, 0x6f, 0xdf, 0xfc, 0x90, 0xfc, 0x20, 0x1d,
        0x71, 0xa3
};
static const unsigned char ietf_rfc9380_3isogeny_map_secp256k1_k_3_2[] = {
        0x29, 0xa6, 0x19, 0x46, 0x91, 0xf9, 0x1a, 0x73, 0x71, 0x52,
        0x09, 0xef, 0x65, 0x12, 0xe5, 0x76, 0x72, 0x28, 0x30, 0xa2,
        0x01, 0xbe, 0x20, 0x18, 0xa7, 0x65, 0xe8, 0x5a, 0x9e, 0xce,
        0xe9, 0x31
};
static const unsigned char ietf_rfc9380_3isogeny_map_secp256k1_k_3_3[] = {
        0x2f, 0x68, 0x4b, 0xda, 0x12, 0xf6, 0x84, 0xbd, 0xa1, 0x2f,
        0x68, 0x4b, 0xda, 0x12, 0xf6, 0x84, 0xbd, 0xa1, 0x2f, 0x68,
        0x4b, 0xda, 0x12, 0xf6, 0x84, 0xbd, 0xa1, 0x2f, 0x38, 0xe3,
        0x8d, 0x84
};
static const unsigned char ietf_rfc9380_3isogeny_map_secp256k1_k_4_0[] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff,
        0xf9, 0x3b
};
static const unsigned char ietf_rfc9380_3isogeny_map_secp256k1_k_4_1[] = {
        0x7a, 0x06, 0x53, 0x4b, 0xb8, 0xbd, 0xb4, 0x9f, 0xd5, 0xe9,
        0xe6, 0x63, 0x27, 0x22, 0xc2, 0x98, 0x94, 0x67, 0xc1, 0xbf,
        0xc8, 0xe8, 0xd9, 0x78, 0xdf, 0xb4, 0x25, 0xd2, 0x68, 0x5c,
        0x25, 0x73
};
static const unsigned char ietf_rfc9380_3isogeny_map_secp256k1_k_4_2[] = {
        0x64, 0x84, 0xaa, 0x71, 0x65, 0x45, 0xca, 0x2c, 0xf3, 0xa7,
        0x0c, 0x3f, 0xa8, 0xfe, 0x33, 0x7e, 0x0a, 0x3d, 0x21, 0x16,
        0x2f, 0x0d, 0x62, 0x99, 0xa7, 0xbf, 0x81, 0x92, 0xbf, 0xd2,
        0xa7, 0x6f
};

/** Integer to Octet String Primitive (I2OSP)
 *
 *  https://datatracker.ietf.org/doc/html/rfc8017#section-4.1
 */
static void I2OSP(unsigned char *output, uint32_t x, uint32_t output_length) {
    int i;
    for (i = (int) output_length - 1; i >= 0; --i) {
        output[i] = (unsigned char) (x & 0xFF);
        x >>= 8;
    }
}

/** Octet String to Integer Primitive (OS2IP)
 *
 *  https://datatracker.ietf.org/doc/html/rfc8017#section-4.2
 */
static void OS2IP(uint32_t *output, const unsigned char *x, uint32_t length) {
    int i;
    for (i = 0; i < (int) length; ++i) {
        *output = (*output) << 8 | x[i];
    }
}

/** XOR two strings together to produce a third string
 *
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

/** The expand_message_xmd function produces a uniformly random byte string using
 *  the cryptographic hash function SHA256 that outputs 256 bits.
 *
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
    unsigned char index2os[1];
    secp256k1_sha256 sha;
    unsigned char **b;
    uint32_t i;

    /* 1.  ell = ceil(len_in_bytes / b_in_bytes) */
    ell = 1 + (len_in_bytes - 1) / IETF_RFC9380_SHA256_B_IN_BYTES;
    /* 2.  ABORT if ell > 255 or len_in_bytes > 65535 or len(DST) > 255 */
    if (ell > 255 || len_in_bytes > 65535 || dst_length > 255) {
        /* ABORT */
        return 0;
    }

    /* 3.  DST_prime = DST || I2OSP(len(DST), 1) */
    dst_prime = (unsigned char *) checked_malloc(&default_error_callback, dst_length + 1);
    memcpy(&dst_prime[0], dst, dst_length);
    I2OSP(&dst_prime[dst_length], dst_length, 1);

    /* msg_prime_length = s_in_bytes + msg_length + 2 + 1 + dst_prime_length */
    msg_prime = (unsigned char *) checked_malloc(&default_error_callback,
                                                 IETF_RFC9380_SHA256_S_IN_BYTES + msg_length + 2 + 1 + dst_length + 1);

    /* 4.  Z_pad = I2OSP(0, s_in_bytes) */
    I2OSP(&msg_prime[0], 0, IETF_RFC9380_SHA256_S_IN_BYTES);

    /* Adding msg to msg_prime (Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime) */
    memcpy(&msg_prime[IETF_RFC9380_SHA256_S_IN_BYTES], msg, msg_length);

    /* 5.  l_i_b_str = I2OSP(len_in_bytes, 2) */
    /* 6.  msg_prime = Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime */
    I2OSP(&msg_prime[IETF_RFC9380_SHA256_S_IN_BYTES + msg_length], len_in_bytes, 2);
    I2OSP(&msg_prime[IETF_RFC9380_SHA256_S_IN_BYTES + msg_length + 2], 0, 1);
    memcpy(&msg_prime[IETF_RFC9380_SHA256_S_IN_BYTES + msg_length + 2 + 1], dst_prime, dst_length + 1);

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

    /* TODO: ell is included?? Maybe yes, but currently it is not */
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

/** The hash_to_field function hashes a byte string msg of arbitrary length into one
 *  or more elements of a field F.
 *
 *  This function works in two steps: it first hashes the input byte string to produce
 *  a uniformly random byte string, and then interprets this byte string as one or more
 *  elements of F.
 *
 *  Out:    field_elems : pointer to an (allocated) array of field elements
 *   In:          msg: a byte string
 *         msg_length: length of msg
 *                dst: a domain separation tag (of at most 255 bytes)
 *         dst_length: actual length of dst
 *              count: length of the uniform byte array to produce in output
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
    for (i = 0; i < count; i++) {
        /* 4.   for j in (0, ..., m - 1): */
        for (j = 0; j < IETF_RFC9380_SECP256K1_m; j++) {
            secp256k1_fe ej;
            /* 5.     elm_offset = L * (j + i * m) */
            elm_offset = IETF_RFC9380_SECP256K1_L * (j + i * IETF_RFC9380_SECP256K1_m);

            /* 6.     tv = substr(uniform_bytes, elm_offset, L) */
            OS2IP(&e[j], &uniform_bytes[elm_offset], IETF_RFC9380_SECP256K1_L);
            /* 7.     e_j = OS2IP(tv) mod p */
            /* Here, e_j is an unsigned int 32, whereas p is (2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1);
             * FIXME: the modulo operation should not be needed here. To be checked */
            /* e[j] = e[j] % IETF_RFC9380_SECP256K1_p; */
        }
        /* 8.   u_i = (e_0, ..., e_(m - 1)) */
        /* TODO: generalize this; here, we consider the specific case of m = 1 (as it is for secp256k1) */
        if (emx_result == 1) {
            /* FIXME: unsafe type casting */
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

/** Implementation of the sqrt_ratio:
 *  https://datatracker.ietf.org/doc/html/rfc9380#straightline-sswu-sqrt-ratio
 *
 * FIXME: possible implementation errors
 *
 *  Returns 1 if (u / v) is square in F; 0 otherwise
 *  Out: y: field element: y = sqrt(u / v) if (u / v) is square in F, and
 *                        y = sqrt(Z * (u / v)) otherwise.
 *  In:  u: field element
 *       v: field element (should be !=0)
 */
static int sqrt_ratio(secp256k1_fe *y, const secp256k1_fe *u, const secp256k1_fe *v) {
    secp256k1_fe ratio, Z;
    int is_square;

    assert(!secp256k1_fe_is_zero(v));

    secp256k1_fe_inv(&ratio, v);
    secp256k1_fe_mul(&ratio, u, &ratio);

    is_square = secp256k1_fe_is_square_var(&ratio);
    if (is_square) {
        secp256k1_fe_sqrt(y, &ratio);
    } else {
        secp256k1_fe_set_int(&Z, IETF_RFC9380_SECP256K1_Z);
        secp256k1_fe_mul(y, &Z, &ratio);
        secp256k1_fe_sqrt(y, y);
    }
    return is_square;
}

static int sgn0(secp256k1_fe *x) {
    /* For secp256k1, m=1. The standard suggests to implement this function as x mod 2, which boils down to
     * checking whether x is odd */
    return secp256k1_fe_is_odd(x);
}

/** Straight-line implementation of the Simplified SWU method for any Weierstrass curve.
 *
 *  The implementation follows the optimized procedure presented in Appendix F.2.2 of RFC9380:
 *  https://datatracker.ietf.org/doc/html/rfc9380#appendix-F.2
 *
 *  Out:  Q: point on the secp256k1 curve
 *   In:  u: field element
 */
static void map_to_curve_simple_swu(
        /*out: */ secp256k1_gej *Q,
        /*in: */ secp256k1_fe *u) {
    secp256k1_fe tv1, tv2, tv3, tv4, tv5, tv6, A, y1;
    unsigned char buffer[32];
    int is_gx1_square, e1;

    /* 01. */secp256k1_fe_sqr(&tv1, u);
    /* 02. */secp256k1_fe_mul_int(&tv1, IETF_RFC9380_SECP256K1_Z);
    /* 03. */secp256k1_fe_sqr(&tv2, &tv1);
    /* 04. */secp256k1_fe_add(&tv2, &tv1);

    /*     */secp256k1_fe_get_b32(buffer, &tv2);
    /*     */secp256k1_fe_set_b32_mod(&tv3, buffer);
    /* 05. */secp256k1_fe_add_int(&tv3, 1);

    /* 06. */secp256k1_fe_mul_int(&tv3, IETF_RFC9380_M2C_B);
    if (!secp256k1_fe_is_zero(&tv2)) {
        /*     */secp256k1_fe_set_b32_mod(&tv4, buffer);
        /* 07. */secp256k1_fe_mul_int(&tv4, -1);
    } else {
        /* 07. */secp256k1_fe_set_int(&tv4, IETF_RFC9380_SECP256K1_Z);
    }
    /*     */secp256k1_fe_set_b32_mod(&A, ietf_rfc9380_m2c_a_prime);
    /* 08. */secp256k1_fe_mul(&tv4, &tv4, &A);
    /* 09. */secp256k1_fe_sqr(&tv2, &tv3);
    /* 10. */secp256k1_fe_sqr(&tv6, &tv4);
    /* 11. */secp256k1_fe_mul(&tv5, &tv6, &A);
    /* 12. */secp256k1_fe_add(&tv2, &tv5);
    /* 13. */secp256k1_fe_mul(&tv2, &tv2, &tv3);
    /* 14. */secp256k1_fe_mul(&tv6, &tv6, &tv4);

    /*     */secp256k1_fe_get_b32(buffer, &tv6);
    /*     */secp256k1_fe_set_b32_mod(&tv5, buffer);
    /* 15. */secp256k1_fe_mul_int(&tv4, IETF_RFC9380_M2C_B);
    /* 16. */secp256k1_fe_add(&tv2, &tv5);
    /* 17. */secp256k1_fe_mul(&Q->x, &tv1, &tv3);

    /*18. (is_gx1_square, y1) = sqrt_ratio(tv2, tv6) */
    /* 18. */is_gx1_square = sqrt_ratio(&y1, &tv2, &tv6);
    /* 19. */secp256k1_fe_mul(&Q->y, &tv1, u);
    /* 20. */secp256k1_fe_mul(&Q->y, &Q->y, &y1);
    if (is_gx1_square) {
        /* 21. */memcpy(&Q->x, &tv3, sizeof(tv3));
        /* 22. */memcpy(&Q->y, &y1, sizeof(tv3));
    }
    /* 23. */ e1 = sgn0(u) == sgn0(&Q->y);
    if (!e1) {
        /* 24. */secp256k1_fe_mul_int(&Q->y, -1);
    }
    /* 25. */secp256k1_fe_inv(&tv4, &tv4);
    /* 25. */secp256k1_fe_mul(&Q->x, &Q->x, &tv4);
    /* 26. return Q = (x, y)*/
}

/** The 3-isogeny map from (x', y') on E' to (x, y) on E.
 *
 *  https://datatracker.ietf.org/doc/html/rfc9380#appx-iso-secp256k1
 *
 *  Out:       Q: point on E
 *  In:  Q_prime: point on E'
 */
static void iso_map(secp256k1_gej *Q, const secp256k1_gej *Q_prime) {
    secp256k1_fe x_num, y_num, x_den, y_den, tmp;
    secp256k1_fe k_13, k_12, k_11, k_10, k_21, k_20, k_33, k_32, k_31, k_30, k_42, k_41, k_40;

    secp256k1_fe_set_b32_mod(&k_10, ietf_rfc9380_3isogeny_map_secp256k1_k_1_0);
    secp256k1_fe_set_b32_mod(&k_11, ietf_rfc9380_3isogeny_map_secp256k1_k_1_1);
    secp256k1_fe_set_b32_mod(&k_12, ietf_rfc9380_3isogeny_map_secp256k1_k_1_2);
    secp256k1_fe_set_b32_mod(&k_13, ietf_rfc9380_3isogeny_map_secp256k1_k_1_3);
    secp256k1_fe_set_b32_mod(&k_20, ietf_rfc9380_3isogeny_map_secp256k1_k_2_0);
    secp256k1_fe_set_b32_mod(&k_21, ietf_rfc9380_3isogeny_map_secp256k1_k_2_1);
    secp256k1_fe_set_b32_mod(&k_30, ietf_rfc9380_3isogeny_map_secp256k1_k_3_0);
    secp256k1_fe_set_b32_mod(&k_31, ietf_rfc9380_3isogeny_map_secp256k1_k_3_1);
    secp256k1_fe_set_b32_mod(&k_32, ietf_rfc9380_3isogeny_map_secp256k1_k_3_2);
    secp256k1_fe_set_b32_mod(&k_33, ietf_rfc9380_3isogeny_map_secp256k1_k_3_3);
    secp256k1_fe_set_b32_mod(&k_40, ietf_rfc9380_3isogeny_map_secp256k1_k_4_0);
    secp256k1_fe_set_b32_mod(&k_41, ietf_rfc9380_3isogeny_map_secp256k1_k_4_1);
    secp256k1_fe_set_b32_mod(&k_42, ietf_rfc9380_3isogeny_map_secp256k1_k_4_2);

    /* x = x_num / x_den, where:
     *   x_num = k_(1,3) * x'^3 + k_(1,2) * x'^2 + k_(1,1) * x' + k_(1,0)
     *   x_den = x'^2 + k_(2,1) * x' + k_(2,0) */
    /* x_num */
    secp256k1_fe_clear(&x_num);
    secp256k1_fe_add(&x_num, &k_10);
    secp256k1_fe_mul(&tmp, &Q_prime->x, &k_11);
    secp256k1_fe_add(&x_num, &tmp);
    secp256k1_fe_mul(&tmp, &Q_prime->x, &Q_prime->x); /* x'^2*/
    secp256k1_fe_mul(&tmp, &tmp, &k_12);
    secp256k1_fe_add(&x_num, &tmp);
    secp256k1_fe_mul(&tmp, &Q_prime->x, &Q_prime->x); /* x'^2*/
    secp256k1_fe_mul(&tmp, &tmp, &Q_prime->x);        /* x'^3*/
    secp256k1_fe_mul(&tmp, &tmp, &k_13);
    secp256k1_fe_add(&x_num, &tmp);

    /* x_den */
    secp256k1_fe_clear(&x_den);
    secp256k1_fe_add(&x_den, &k_20);
    secp256k1_fe_mul(&tmp, &Q_prime->x, &k_21);
    secp256k1_fe_add(&x_den, &tmp);
    secp256k1_fe_mul(&tmp, &Q_prime->x, &Q_prime->x); /* x'^2*/
    secp256k1_fe_add(&x_den, &tmp);

    /* x = x_num / x_den */
    secp256k1_fe_inv(&x_den, &x_den);                   /* x_den = x_den^-1 */
    secp256k1_fe_mul(&Q->x, &x_num, &x_den);

    /* y = y' * y_num / y_den, where:
     *   y_num = k_(3,3) * x'^3 + k_(3,2) * x'^2 + k_(3,1) * x' + k_(3,0)
     *   y_den = x'^3 + k_(4,2) * x'^2 + k_(4,1) * x' + k_(4,0)  */

    /* y_num */
    secp256k1_fe_clear(&y_num);
    secp256k1_fe_add(&y_num, &k_30);
    secp256k1_fe_mul(&tmp, &Q_prime->x, &k_31);
    secp256k1_fe_add(&y_num, &tmp);
    secp256k1_fe_mul(&tmp, &Q_prime->x, &Q_prime->x); /* x'^2*/
    secp256k1_fe_mul(&tmp, &tmp, &k_32);
    secp256k1_fe_add(&y_num, &tmp);
    secp256k1_fe_mul(&tmp, &Q_prime->x, &Q_prime->x); /* x'^2*/
    secp256k1_fe_mul(&tmp, &tmp, &Q_prime->x);        /* x'^3*/
    secp256k1_fe_mul(&tmp, &tmp, &k_33);
    secp256k1_fe_add(&y_num, &tmp);

    /* y_den */
    secp256k1_fe_clear(&y_den);
    secp256k1_fe_add(&y_den, &k_40);
    secp256k1_fe_mul(&tmp, &Q_prime->x, &k_41);
    secp256k1_fe_add(&y_den, &tmp);
    secp256k1_fe_mul(&tmp, &Q_prime->x, &Q_prime->x); /* x'^2*/
    secp256k1_fe_mul(&tmp, &tmp, &k_42);
    secp256k1_fe_add(&y_den, &tmp);
    secp256k1_fe_mul(&tmp, &Q_prime->x, &Q_prime->x); /* x'^2*/
    secp256k1_fe_mul(&tmp, &tmp, &Q_prime->x);        /* x'^3*/
    secp256k1_fe_add(&y_num, &tmp);

    /* y = y' * y_num / y_den */
    secp256k1_fe_inv(&y_den, &y_den);                   /* y_den = y_den^-1 */
    secp256k1_fe_mul(&tmp, &y_num, &y_den);
    secp256k1_fe_mul(&Q->y, &Q_prime->y, &tmp);

    secp256k1_fe_clear(&x_num);
    secp256k1_fe_clear(&x_den);
    secp256k1_fe_clear(&y_num);
    secp256k1_fe_clear(&y_den);
    secp256k1_fe_clear(&tmp);
}

/** The function map_to_curve calculates a point on the elliptic curve E from
 *  an element of the finite field F over which E is defined.
 *
 *  For secp256k1, RFC9380 requires using the Simplified Shallue-van de Woestijne-Ulas
 *  (SWU) method for AB == 0 (Section 6.6.3).
 *  https://datatracker.ietf.org/doc/html/rfc9380#name-simplified-swu-for-ab-0
 *
 *  Out:   Q: point on secp256k1 curve
 *   In:   u: element of the field
 */
static void map_to_curve(secp256k1_gej *Q, secp256k1_fe *u) {
    /* (x', y') = map_to_curve_simple_swu(u)    # (x', y') is on E' */
    map_to_curve_simple_swu(Q, u);
    /* (x, y) = iso_map(x', y')               # (x, y) is on E */
    iso_map(Q, Q);
    /* return (x, y) */
}

/** clear_cofactor(P) takes as input any point on the curve
 *  and produces as output a point in the prime-order (sub)group G.
 *
 *  The cofactor can always be cleared via scalar multiplication by h.
 *     clear_cofactor(P) := h_eff * P
 *  For elliptic curves where h = 1, i.e., the curves with a prime number
 *  of points, no operation is required.
 *  For secp256k1, h_eff: 1
 *
 *  Out,In: P: point on secp256k1 curve
 */
static void clear_cofactor(secp256k1_gej *P) {
    /* Nothing to do for secp256k1 */
    (void *) P;
}

/** hash_to_curve is a uniform encoding from byte strings to points in G.
 *  That is, the distribution of its output is statistically close to uniform in G.
 *  Ref: https://datatracker.ietf.org/doc/html/rfc9380#name-encoding-byte-strings-to-el
 *
 *  Out:   P: a point on the secp256k1 elliptic curve
 *   In:        msg: a byte string
 *       msg_length: length of msg
 *              dst: a domain separation tag (of at most 255 bytes)
 *       dst_length: actual length of dst
 */
static void hash_to_curve(secp256k1_gej *P,
                          const unsigned char *msg, uint32_t msg_length,
                          const unsigned char *dst, uint32_t dst_length) {
    secp256k1_fe u[2];
    secp256k1_gej Q[2];
    hash_to_field(u, msg, msg_length, dst, dst_length, 2);
    map_to_curve(&Q[0], &u[0]);
    map_to_curve(&Q[1], &u[1]);
    secp256k1_gej_add_var(P, &Q[0], &Q[1], NULL);
    clear_cofactor(P);
}

#endif /* LIBSECP256K1_HASH_TO_CURVE_H */
