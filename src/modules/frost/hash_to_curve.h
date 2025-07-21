#ifndef SECP256K1_MODULE_FROST_HASH_TO_CURVE_H
#define SECP256K1_MODULE_FROST_HASH_TO_CURVE_H

#include "bigint.h"
#include "../../../include/secp256k1.h"
#include "../../../include/secp256k1_frost.h"

/* p = 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1
 * it is the default p parameter of the secp256k1 elliptic curve */
#define IETF_RFC9380_SECP256K1_m (1U)
#define IETF_RFC9380_SECP256K1_L (48U)
#define IETF_RFC9380_SECP256K1_Z (-11)
#define IETF_RFC9380_SHA256_B_IN_BYTES (32U)
#define IETF_RFC9380_SHA256_S_IN_BYTES (64U)
#define IETF_RFC9380_M2C_B (1771U)


/* ******* hash to curve constants ******* */

static const unsigned char long_dst_prefix[17] = {'H','2','C','-','O','V','E','R','S','I','Z','E','-','D','S','T','-'};

static const unsigned char ietf_rfc9380_A_prime[] = {
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


static const bigint_internal secp256k1_p_bigint = {
    {
        0xFFFFFFFEFFFFFC2FULL,  /* limbs[0] - least significant 64 bits */
        0xFFFFFFFFFFFFFFFFULL,  /* limbs[1] */
        0xFFFFFFFFFFFFFFFFULL,  /* limbs[2] */
        0xFFFFFFFFFFFFFFFFULL,  /* limbs[3] - most significant 64 bits */
        0x0000000000000000ULL,  /* limbs[4] - unused */
        0x0000000000000000ULL,  /* limbs[5] - unused */
        0x0000000000000000ULL,  /* limbs[6] - unused */
        0x0000000000000000ULL   /* limbs[7] - unused */
    },
    4  /* nlimbs - uses 4 limbs (256 bits) */
};

static const bigint_internal secp256k1_n_bigint = {
    {
        0xBFD25E8CD0364141ULL,  /* limbs[0] - LSB */
        0xBAAEDCE6AF48A03BULL,  /* limbs[1] */
        0xFFFFFFFFFFFFFFFEULL,  /* limbs[2] */
        0xFFFFFFFFFFFFFFFFULL,  /* limbs[3] - MSB */
        0x0000000000000000ULL,  /* limbs[4] - unused */
        0x0000000000000000ULL,  /* limbs[5] - unused */
        0x0000000000000000ULL,  /* limbs[6] - unused */
        0x0000000000000000ULL   /* limbs[7] - unused */
    },
    4  /* nlimbs */
};

/* ******* end of hash to curve constants ******* */

/** Integer to Octet String Primitive (I2OSP)
 *
 * Converts a bigint_internal `x` to a big-endian octet string of length `len`.
 * Returns 1 on success, 0 on failure (e.g., x ≥ 256^len).
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

/**
 * Converts a big-endian byte string `in[0..len-1]` to a bigint_internal struct.
 * Result is stored in `*out`.
 * Assumes len ≤ 64 (512 bits). Excess bytes are ignored.
 */
static void OS2IP(bigint_internal *out, const uint8_t *in, size_t len) {
    size_t i;
    memset(out, 0, sizeof(bigint_internal));
    out->nlimbs = (len + 7) / 8;

    for (i = 0; i < len; i++) {
        size_t limb = (len - 1 - i) / 8;
        size_t shift = ((len - 1 - i) % 8) * 8;
        out->limbs[limb] |= ((uint64_t)in[i]) << shift;
    }

    while (out->nlimbs > 0 && out->limbs[out->nlimbs - 1] == 0) {
        out->nlimbs--;
    }
}


/** XOR two strings together to produce a third string
 *
 *  dest[0,..,n-1] := src_a[0,..,n-1] ^ src_b[0,..,n-1]
 */
static void strxor(unsigned char *dest, const unsigned char *src_a, const unsigned char *src_b, size_t n) {
    size_t i;

    /* assert no pointer overflow */
    VERIFY_CHECK(src_a + n > src_a);
    VERIFY_CHECK(src_b + n > src_b);
    VERIFY_CHECK(dest + n > dest);

    for (i = 0; i < n; i++) {
        dest[i] = src_a[i] ^ src_b[i];
    }
}

static void compute_dst_prime(unsigned char *dst_prime, const unsigned char *dst, uint32_t dst_length) {
    /* 3.  DST_prime = DST || I2OSP(len(DST), 1) */
    memcpy(&dst_prime[0], dst, dst_length);
    I2OSP(&dst_prime[dst_length], dst_length, 1);
}

static void compute_msg_prime(unsigned char *msg_prime, const unsigned char *msg, uint32_t msg_length,
                               const unsigned char *dst_prime, uint32_t dst_length,
                               uint32_t len_in_bytes) {/* 4.  Z_pad = I2OSP(0, s_in_bytes) */
    /* 4.  Z_pad = I2OSP(0, s_in_bytes) */
    I2OSP(&msg_prime[0], 0, IETF_RFC9380_SHA256_S_IN_BYTES);

    /* Adding msg to msg_prime (Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime) */
    memcpy(&msg_prime[IETF_RFC9380_SHA256_S_IN_BYTES], msg, msg_length);

    /* 5.  l_i_b_str = I2OSP(len_in_bytes, 2) */
    /* 6.  msg_prime = Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime */
    I2OSP(&msg_prime[IETF_RFC9380_SHA256_S_IN_BYTES + msg_length], len_in_bytes, 2);
    I2OSP(&msg_prime[IETF_RFC9380_SHA256_S_IN_BYTES + msg_length + 2], 0, 1);
    memcpy(&msg_prime[IETF_RFC9380_SHA256_S_IN_BYTES + msg_length + 2 + 1], dst_prime, dst_length + 1);
}

static unsigned char* reduce_dst_if_needed_xmd(const unsigned char *dst, uint32_t *dst_length){
    int reduced;
    secp256k1_sha256 sha;
    unsigned char *dest_dst;
    reduced = *dst_length > 255;
    if (reduced) {
        dest_dst = (unsigned char *) checked_malloc(&default_error_callback, SHA256_SIZE);
        secp256k1_sha256_initialize(&sha);
        secp256k1_sha256_write(&sha, long_dst_prefix, 17);
        secp256k1_sha256_write(&sha, dst, *dst_length);
        secp256k1_sha256_finalize(&sha, &dest_dst[0]);
        *dst_length = SHA256_SIZE;
    } else {
        dest_dst = (unsigned char *) checked_malloc(&default_error_callback, *dst_length);
        memcpy(dest_dst, dst, *dst_length);
    }
    return dest_dst;
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
    unsigned char *dst_, *dst_prime, *msg_prime, *uniform_bytes;
    unsigned char index2os[1];
    secp256k1_sha256 sha;
    unsigned char **b;
    uint32_t i;

    dst_ = reduce_dst_if_needed_xmd(dst, &dst_length);

    /* 1.  ell = ceil(len_in_bytes / b_in_bytes) */
    ell = 1 + (len_in_bytes - 1) / IETF_RFC9380_SHA256_B_IN_BYTES;
    /* 2.  ABORT if ell > 255 or len_in_bytes > 65535 or len(DST) > 255 */
    if (ell > 255 || len_in_bytes > 65535 || dst_length > 255) {
        /* ABORT */
        return 0;
    }

    /* 3.  DST_prime = DST || I2OSP(len(DST), 1) */
    dst_prime = (unsigned char *) checked_malloc(&default_error_callback, dst_length + 1);
    compute_dst_prime(dst_prime, dst_, dst_length);

    /* msg_prime_length = s_in_bytes + msg_length + 2 + 1 + dst_prime_length */
    msg_prime = (unsigned char *) checked_malloc(&default_error_callback,
                                                 IETF_RFC9380_SHA256_S_IN_BYTES + msg_length + 2 + 1 + dst_length + 1);
    /* 4.  Z_pad = I2OSP(0, s_in_bytes) */
    /* 5.  l_i_b_str = I2OSP(len_in_bytes, 2) */
    /* 6.  msg_prime = Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime */
    compute_msg_prime(msg_prime, msg, msg_length, dst_prime, dst_length, len_in_bytes);

    /* Allocating b_0, ...,  = H(msg_prime)  */
    b = malloc((ell + 1) * sizeof b);
    for (i = 0; i < ell + 1; i++) {
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

    /* 9.  for i in (2, ..., ell):
     * 10.    b_i = H(strxor(b_0, b_(i - 1)) || I2OSP(i, 1) || DST_prime) */
    for (i = 2; i < ell + 1; i++) {
        secp256k1_sha256_initialize(&sha);
        strxor(b[i], b[0], b[i - 1], SHA256_SIZE);
        secp256k1_sha256_write(&sha, b[i], SHA256_SIZE);
        I2OSP(index2os, i, 1);
        secp256k1_sha256_write(&sha, index2os, 1);
        secp256k1_sha256_write(&sha, dst_prime, dst_length + 1);
        secp256k1_sha256_finalize(&sha, b[i]);
    }

    /* 11. uniform_bytes = b_1 || ... || b_ell */
    uniform_bytes = (unsigned char *) checked_malloc(&default_error_callback, ell * SHA256_SIZE);
    for (i = 1; i < ell + 1; i++) {
        memcpy(&uniform_bytes[(i - 1) * SHA256_SIZE], b[i], SHA256_SIZE);
    }

    /* 12. return substr(uniform_bytes, 0, len_in_bytes) */
    memcpy(output, uniform_bytes, len_in_bytes);

    /* cleaning out dynamically allocated memory */
    free(dst_);
    if (dst_prime != NULL) {
        free(dst_prime);
    }
    if (msg_prime != NULL) {
        free(msg_prime);
    }
    if (uniform_bytes != NULL) {
        free(uniform_bytes);
    }
    for (i = 0; i < ell + 1; i++) {
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
    unsigned char *uniform_bytes;
    int emx_result;

    /* 1. len_in_bytes = count * m * L */
    len_in_bytes = count * IETF_RFC9380_SECP256K1_m * IETF_RFC9380_SECP256K1_L;

    /* 2. uniform_bytes = expand_message(msg, DST, len_in_bytes) */
    uniform_bytes = (unsigned char *) checked_malloc(&default_error_callback,
                                                     len_in_bytes);
    emx_result = expand_message_xmd(uniform_bytes, msg, msg_length, dst, dst_length, len_in_bytes);
    if (emx_result == 0) {
        return;
    }

    /* 3. for i in (0, ..., count - 1): */
    for (i = 0; i < count; i++) {
        /* 4.   for j in (0, ..., m - 1): */
        for (j = 0; j < IETF_RFC9380_SECP256K1_m; j++) {
            unsigned char *tv;
            uint8_t reduced[32];
            bigint_internal x, r;

            /* 5.     elm_offset = L * (j + i * m) */
            elm_offset = IETF_RFC9380_SECP256K1_L * (j + i * IETF_RFC9380_SECP256K1_m);

            /* 6.     tv = substr(uniform_bytes, elm_offset, L) */
            tv = uniform_bytes + elm_offset;

            /* 7.     e_j = OS2IP(tv) mod p */
            /* 8.   u_i = (e_0, ..., e_(m - 1)) */
            /*    we write directly u_i (field_elements[i]) as m is equal to 1 */
            OS2IP(&x, tv, 48);

            if (bigint_mod(&r, &x, &secp256k1_p_bigint) == -1) {
                /* Error while performing modulus on a bigint: this should never happen
                * as we always provide a valid bigint as input (it is computed internally) */
                memset(reduced, 0, 32);
                secp256k1_fe_set_b32_mod(&field_elems[i], reduced);
                continue;
            }

            if (bigint_to_bytes_be(reduced, &r) == -1) {
                /* Error while converting bigint to a byte array: this should never happen
                 * as we always provide a valid bigint as input (it is computed internally) */
                memset(reduced, 0, 32);
            }

            secp256k1_fe_set_b32_mod(&field_elems[i], reduced);  /* assumes already mod p */
        }
    }

    /* Clean-up temporary variables */
    if (uniform_bytes != NULL) {
        free(uniform_bytes);
    }

    /*  return (u_0, ..., u_(count - 1)) */
}

static void hash_to_scalar_field(unsigned char *out32,
                                 const unsigned char *msg, uint32_t msg_length,
                                 const unsigned char *dst, uint32_t dst_length) {
    uint32_t len_in_bytes = 1 * IETF_RFC9380_SECP256K1_m * IETF_RFC9380_SECP256K1_L;
    unsigned char *uniform_bytes;
    unsigned char *tv;
    uint8_t reduced[32];
    bigint_internal x, r;
    int emx_result;

    uniform_bytes = (unsigned char *) checked_malloc(&default_error_callback, len_in_bytes);
    emx_result = expand_message_xmd(uniform_bytes, msg, msg_length, dst, dst_length, len_in_bytes);
    if (emx_result == 0) {
        free(uniform_bytes);
        return;
    }

    tv = uniform_bytes;
    OS2IP(&x, tv, 48);

    if (bigint_mod(&r, &x, &secp256k1_n_bigint) == -1) {
        /* Error while performing modulus on a bigint: this should never happen
         * as we always provide a valid bigint as input (it is computed internally) */
        memset(out32, 0, 32);
        free(uniform_bytes);
        return;
    }

    if (bigint_to_bytes_be(reduced, &r) == -1) {
        /* Error while converting bigint to a byte array: this should never happen
         * as we always provide a valid bigint as input (it is computed internally) */
        memset(out32, 0, 32);
        free(uniform_bytes);
        return;
    }

    memcpy(out32, reduced, 32);
    free(uniform_bytes);
}

/** Implementation of the sqrt_ratio:
 *  https://datatracker.ietf.org/doc/html/rfc9380#straightline-sswu-sqrt-ratio
 *
 * This function replicates the implementation of sqrtRatio provided in h2c-go-ref
 *  (https://github.com/armfazh/h2c-go-ref/blob/f7ab85f82259301238847f66915aebacf21dd408/mapping/sswu.go#L67)
 *
 *  Returns 1 if (u / v) is square in F; 0 otherwise
 *  Out: y: field element: y = sqrt(u / v) if (u / v) is square in F, and
 *                         y = sqrt(Z * (u / v)) otherwise.
 *  In:  u: field element
 *       v: field element (should be !=0)
 */
static int sqrt_ratio(secp256k1_fe *y, const secp256k1_fe *u, secp256k1_fe *v) {
    int isQR;
    secp256k1_fe y1, Z;

    secp256k1_fe_inv(&y1, v);
    secp256k1_fe_mul(&y1, &y1, u);
    isQR = secp256k1_fe_is_square_var(&y1);
    if (!isQR){
        secp256k1_fe_set_int(&Z, -1 * IETF_RFC9380_SECP256K1_Z);
        secp256k1_fe_negate(&Z, &Z, IETF_RFC9380_SECP256K1_m);
        secp256k1_fe_mul(&y1, &y1, &Z);
    }
    secp256k1_fe_sqrt(y, &y1);

    /* Clean-up temporary variables */
    secp256k1_fe_clear(&y1);
    secp256k1_fe_clear(&Z);

    return isQR;
}

/**
 * This function returns either 0 or 1 indicating the "sign" of x,
 * where sgn0(x) == 1 just when x is "negative".
 */
static int sgn0(secp256k1_fe *x) {
    /* The [standard](https://datatracker.ietf.org/doc/html/rfc9380#sgn0-function) suggests:
     * When m == 1 (as for secp256k1), sgn0 can be significantly simplified:
     *      sgn0_m_eq_1(x)
     * Input: x, an element of GF(p).
     * Output: 0 or 1.
     * Steps:
     *  1. return x mod 2
     */
    secp256k1_fe_normalize(x);
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
        /*out: */ secp256k1_ge *Q,
        /*in: */ secp256k1_fe *u) {
    secp256k1_fe tv1, tv2, tv3, tv4, tv5, tv6, A, y1, Z, B;
    int is_gx1_square, e1;

    secp256k1_fe_set_int(&Z, -1 * IETF_RFC9380_SECP256K1_Z);
    secp256k1_fe_negate(&Z, &Z, IETF_RFC9380_SECP256K1_m);
    secp256k1_fe_set_int(&B, IETF_RFC9380_M2C_B);

    /* 01. */secp256k1_fe_sqr(&tv1, u);
    /* 02. */secp256k1_fe_mul(&tv1, &tv1, &Z);
    /* 03. */secp256k1_fe_sqr(&tv2, &tv1);
    /* 04. */secp256k1_fe_add(&tv2, &tv1);
    /*     */memcpy(&tv3, &tv2, sizeof(secp256k1_fe));
    /* 05. */secp256k1_fe_add_int(&tv3, 1);
    /* 06. */secp256k1_fe_mul(&tv3, &tv3, &B);

    /* 07. tv4 = CMOV(Z, -tv2, tv2 != 0)*/
    secp256k1_fe_normalize(&tv2);
    if (!secp256k1_fe_is_zero(&tv2)) {
        memcpy(&tv4, &tv2, sizeof(secp256k1_fe));
    } else {
        secp256k1_fe_set_int(&tv4, -1 * IETF_RFC9380_SECP256K1_Z);
    }
    secp256k1_fe_negate(&tv4, &tv4, IETF_RFC9380_SECP256K1_m);

    /*     */secp256k1_fe_set_b32_mod(&A, ietf_rfc9380_A_prime);
    /* 08. */secp256k1_fe_mul(&tv4, &tv4, &A);
    /* 09. */secp256k1_fe_sqr(&tv2, &tv3);
    /* 10. */secp256k1_fe_sqr(&tv6, &tv4);
    /* 11. */secp256k1_fe_mul(&tv5, &tv6, &A);
    /* 12. */secp256k1_fe_add(&tv2, &tv5);
    /* 13. */secp256k1_fe_mul(&tv2, &tv2, &tv3);
    /* 14. */secp256k1_fe_mul(&tv6, &tv6, &tv4);
    /* 15. */secp256k1_fe_mul(&tv5, &tv6, &B);
    /* 16. */secp256k1_fe_add(&tv2, &tv5);
    /* 17. */secp256k1_fe_mul(&Q->x, &tv1, &tv3);

    /* 18. (is_gx1_square, y1) = sqrt_ratio(tv2, tv6) */
    /* 18. */is_gx1_square = sqrt_ratio(&y1, &tv2, &tv6);
    /* 19. */secp256k1_fe_mul(&Q->y, &tv1, u);
    /* 20. */secp256k1_fe_mul(&Q->y, &Q->y, &y1);
    if (is_gx1_square) {
        /* 21. */memcpy(&Q->x, &tv3, sizeof(secp256k1_fe));
        /* 22. */memcpy(&Q->y, &y1, sizeof(secp256k1_fe));
    }
    /* 23. */ e1 = sgn0(u) == sgn0(&Q->y);
    if (!e1) {
        /* 24. */secp256k1_fe_negate(&Q->y, &Q->y, IETF_RFC9380_SECP256K1_m);
    }
    /* 25. */secp256k1_fe_inv(&tv4, &tv4);
    /* 25. */secp256k1_fe_mul(&Q->x, &Q->x, &tv4);

    /* Clean-up temporary variables */
    secp256k1_fe_clear(&tv1);
    secp256k1_fe_clear(&tv2);
    secp256k1_fe_clear(&tv3);
    secp256k1_fe_clear(&tv4);
    secp256k1_fe_clear(&tv5);
    secp256k1_fe_clear(&tv6);
    secp256k1_fe_clear(&A);
    secp256k1_fe_clear(&y1);
    secp256k1_fe_clear(&Z);
    secp256k1_fe_clear(&B);

    /* 26. return Q = (x, y)*/
}

/** The 3-isogeny map from (x', y') on E' to (x, y) on E.
 *
 *  https://datatracker.ietf.org/doc/html/rfc9380#appx-iso-secp256k1
 *
 *  Out:       Q: point on E
 *  In:  Q_prime: point on E'
 */
static void iso_map(secp256k1_ge *Q, const secp256k1_ge *Q_prime) {
    secp256k1_fe x_num, y_num, x_den, y_den, tmp, tmp2, x_prime, x_prime_2, x_prime_3, y_prime;
    secp256k1_fe k_13, k_12, k_11, k_10, k_21, k_20, k_33, k_32, k_31, k_30, k_42, k_41, k_40;

    secp256k1_fe_set_int(&Q->x, 0);
    secp256k1_fe_set_int(&Q->y, 0);

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

    memcpy(&x_prime, &Q_prime->x, sizeof(secp256k1_fe));
    memcpy(&y_prime, &Q_prime->y, sizeof(secp256k1_fe));
    secp256k1_fe_normalize(&x_prime);
    secp256k1_fe_normalize(&y_prime);
    secp256k1_fe_sqr(&x_prime_2, &x_prime);                       /* x'^2*/
    secp256k1_fe_mul(&x_prime_3, &x_prime, &x_prime_2);         /* x'^3*/

    secp256k1_fe_set_int(&x_num, 0);
    secp256k1_fe_set_int(&x_den, 0);
    secp256k1_fe_set_int(&y_num, 0);
    secp256k1_fe_set_int(&y_den, 0);

    /* x = x_num / x_den, where:
     *   x_num = k_(1,3) * x'^3 + k_(1,2) * x'^2 + k_(1,1) * x' + k_(1,0)
     *   x_den = x'^2 + k_(2,1) * x' + k_(2,0) */

    /* x_num */
    secp256k1_fe_add(&x_num, &k_10);
    secp256k1_fe_mul(&tmp, &x_prime, &k_11);
    secp256k1_fe_add(&x_num, &tmp);
    secp256k1_fe_mul(&tmp, &x_prime_2, &k_12);
    secp256k1_fe_add(&x_num, &tmp);
    secp256k1_fe_mul(&tmp, &x_prime_3, &k_13);
    secp256k1_fe_add(&x_num, &tmp);

    /* x_den */
    secp256k1_fe_add(&x_den, &k_20);
    secp256k1_fe_mul(&tmp, &x_prime, &k_21);
    secp256k1_fe_add(&x_den, &tmp);
    secp256k1_fe_add(&x_den, &x_prime_2);

    /* x = x_num / x_den */
    secp256k1_fe_normalize(&x_num);
    secp256k1_fe_normalize(&x_den);
    secp256k1_fe_inv(&tmp, &x_den);                   /* x_den = x_den^-1 */
    secp256k1_fe_mul(&Q->x, &x_num, &tmp);

    /* y = y' * y_num / y_den, where:
     *   y_num = k_(3,3) * x'^3 + k_(3,2) * x'^2 + k_(3,1) * x' + k_(3,0)
     *   y_den = x'^3 + k_(4,2) * x'^2 + k_(4,1) * x' + k_(4,0)  */

    /* y_num */
    secp256k1_fe_add(&y_num, &k_30);
    secp256k1_fe_mul(&tmp, &x_prime, &k_31);
    secp256k1_fe_add(&y_num, &tmp);
    secp256k1_fe_mul(&tmp, &x_prime_2, &k_32);
    secp256k1_fe_add(&y_num, &tmp);
    secp256k1_fe_mul(&tmp, &x_prime_3, &k_33);
    secp256k1_fe_add(&y_num, &tmp);

    /* y_den */
    secp256k1_fe_add(&y_den, &k_40);
    secp256k1_fe_mul(&tmp, &x_prime, &k_41);
    secp256k1_fe_add(&y_den, &tmp);
    secp256k1_fe_mul(&tmp, &x_prime_2, &k_42);
    secp256k1_fe_add(&y_den, &tmp);
    secp256k1_fe_add(&y_den, &x_prime_3);


    /* y = y' * y_num / y_den */
    secp256k1_fe_normalize(&y_num);
    secp256k1_fe_normalize(&y_den);

    secp256k1_fe_inv(&tmp, &y_den);                   /* y_den = y_den^-1 */
    secp256k1_fe_mul(&tmp2, &y_num, &tmp);
    secp256k1_fe_mul(&Q->y, &y_prime, &tmp2);

    secp256k1_fe_normalize(&Q->x);
    secp256k1_fe_normalize(&Q->y);
    Q->infinity = 0;

    /* Clean-up temporary variables */
    secp256k1_fe_clear(&x_num);
    secp256k1_fe_clear(&x_den);
    secp256k1_fe_clear(&y_num);
    secp256k1_fe_clear(&y_den);
    secp256k1_fe_clear(&tmp);
    secp256k1_fe_clear(&tmp2);
    secp256k1_fe_clear(&x_prime);
    secp256k1_fe_clear(&y_prime);
    secp256k1_fe_clear(&x_prime_2);
    secp256k1_fe_clear(&x_prime_3);
    secp256k1_fe_clear(&k_10);
    secp256k1_fe_clear(&k_11);
    secp256k1_fe_clear(&k_12);
    secp256k1_fe_clear(&k_13);
    secp256k1_fe_clear(&k_20);
    secp256k1_fe_clear(&k_21);
    secp256k1_fe_clear(&k_30);
    secp256k1_fe_clear(&k_31);
    secp256k1_fe_clear(&k_32);
    secp256k1_fe_clear(&k_33);
    secp256k1_fe_clear(&k_40);
    secp256k1_fe_clear(&k_41);
    secp256k1_fe_clear(&k_42);
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
    secp256k1_ge Q_prime, Q_ge;
    /* (x', y') = map_to_curve_simple_swu(u)    # (x', y') is on E' */
    map_to_curve_simple_swu(&Q_prime, u);
    /* (x, y) = iso_map(x', y')                 # (x, y) is on E */
    iso_map(&Q_ge, &Q_prime);
    /* return (x, y) */
    secp256k1_gej_set_ge(Q, &Q_ge);
    /* Clean-up temporary variables */
    secp256k1_ge_clear(&Q_prime);
    secp256k1_ge_clear(&Q_ge);
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
    (void) P;
}

/** hash_to_curve is a uniform encoding from byte strings to points in G.
 *  That is, the distribution of its output is statistically close to uniform in G.
 *  Ref: https://datatracker.ietf.org/doc/html/rfc9380#name-encoding-byte-strings-to-el
 *
 *  This corresponds to secp256k1_XMD:SHA-256_SSWU_RO_.
 *   https://datatracker.ietf.org/doc/html/rfc9380#section-8.7
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

    /* Clean-up temporary variables */
    {
        int i;
        for (i = 0; i < 2; i++){
            secp256k1_fe_clear(&u[i]);
            secp256k1_gej_clear(&Q[i]);
        }
    }
}

/** encode_to_curve is a nonuniform encoding from byte strings to points in G.
 *  That is, the distribution of its output is not uniformly random in G
 *  Ref: https://datatracker.ietf.org/doc/html/rfc9380#name-encoding-byte-strings-to-el
 *
 *  This corresponds to secp256k1_XMD:SHA-256_SSWU_NU_.
 *   https://datatracker.ietf.org/doc/html/rfc9380#section-8.7
 *
 *  Out:   P: a point on the secp256k1 elliptic curve
 *   In:        msg: a byte string
 *       msg_length: length of msg
 *              dst: a domain separation tag (of at most 255 bytes)
 *       dst_length: actual length of dst
 */
static void encode_to_curve(secp256k1_gej *P,
                          const unsigned char *msg, uint32_t msg_length,
                          const unsigned char *dst, uint32_t dst_length) {
    secp256k1_fe u;
    hash_to_field(&u, msg, msg_length, dst, dst_length, 1);
    map_to_curve(P, &u);
    clear_cofactor(P);

    /* Clean-up temporary variables */
    secp256k1_fe_clear(&u);
}

#endif /* SECP256K1_MODULE_FROST_HASH_TO_CURVE_H */
