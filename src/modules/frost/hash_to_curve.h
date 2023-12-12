#ifndef LIBSECP256K1_HASH_TO_CURVE_H
#define LIBSECP256K1_HASH_TO_CURVE_H

#include "../../../include/secp256k1.h"
#include "../../../include/secp256k1_frost.h"

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
 *  msg, a byte string.
- DST, a byte string of at most 255 bytes.
  See below for information on using longer DSTs.
- len_in_bytes, the length of the requested output in bytes,
  not greater than the lesser of (255 * b_in_bytes) or 2^16-1

Output:
- uniform_bytes, a byte string.
 */
static int expand_message_xmd(
        /*out: */
        /*in: */ unsigned char *msg, uint32_t msg_length,
        /*in: */ unsigned char *dst, uint32_t dst_length,
                 uint32_t len_in_bytes) {
 /*
  *
Steps:
1.  ell = ceil(len_in_bytes / b_in_bytes)
2.  ABORT if ell > 255 or len_in_bytes > 65535 or len(DST) > 255
3.  DST_prime = DST || I2OSP(len(DST), 1)
4.  Z_pad = I2OSP(0, s_in_bytes)
5.  l_i_b_str = I2OSP(len_in_bytes, 2)
6.  msg_prime = Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime
7.  b_0 = H(msg_prime)
8.  b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
9.  for i in (2, ..., ell):
10.    b_i = H(strxor(b_0, b_(i - 1)) || I2OSP(i, 1) || DST_prime)
11. uniform_bytes = b_1 || ... || b_ell
12. return substr(uniform_bytes, 0, len_in_bytes)
  * */
 uint32_t ell;
 ell = 1 + (len_in_bytes - 1) / IETF_RFC9380_SHA256_B_IN_BYTES;
 if (ell > 255 || len_in_bytes > 65535 || dst_length > 255) {
     /* ABORT */
     return 0;
 }

 

}

static void hash_to_field(
        /*out: */
        /*in: */ unsigned char *msg, uint32_t msg_length, uint32_t count) {

    /*
   Parameters:
   - DST, a domain separation tag (see Section 3.1).
   - F, a finite field of characteristic p and order q = p^m.
   - p, the characteristic of F (see immediately above).
   - m, the extension degree of F, m >= 1 (see immediately above).
   - L = ceil((ceil(log2(p)) + k) / 8), where k is the security
     parameter of the suite (e.g., k = 128).
   - expand_message, a function that expands a byte string and
     domain separation tag into a uniformly random byte string
     (see Section 5.3).
   - (u_0, ..., u_(count - 1)), a list of field elements.

   Steps:
   1. len_in_bytes = count * m * L
   2. uniform_bytes = expand_message(msg, DST, len_in_bytes)
   3. for i in (0, ..., count - 1):
   4.   for j in (0, ..., m - 1):
   5.     elm_offset = L * (j + i * m)
   6.     tv = substr(uniform_bytes, elm_offset, L)
   7.     e_j = OS2IP(tv) mod p
   8.   u_i = (e_0, ..., e_(m - 1))
   9. return (u_0, ..., u_(count - 1))
     */
    uint32_t len_in_bytes;

    len_in_bytes = count * IETF_RFC9380_SECP256K1_m * IETF_RFC9380_SECP256K1_L;


}

/*
 * The function hash_to_field hashes arbitrary-length byte strings to
 * a list of one or more elements of a finite field F;
 */
static void map_to_curve(
        /*out: */ secp256k1_gej Q,
        /*in: */ unsigned char *msg, uint32_t msg_length, uint32_t count) {

    /*
     * hash_to_field(msg, count)

      Inputs:
      - msg, a byte string containing the message to hash.
      - count, the number of elements of F to output.

      Outputs:
      - (u_0, ..., u_(count - 1)), a list of field elements.

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
 *  https://datatracker.ietf.org/doc/html/rfc9380
 */
static int hash_to_curve(
        /*out: */
        /*in: */ const unsigned char *msg, uint32_t msg_length) {

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
    unsigned char output[32];
    uint32_t value, length;

    value = 12;
    length = 32;
    I2OSP(output, value, length);

    OS2IP(&value, output, length);
    clear_cofactor(&point);

    return 1;
}

#endif /* LIBSECP256K1_HASH_TO_CURVE_H */
