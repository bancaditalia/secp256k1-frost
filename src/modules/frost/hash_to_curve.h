#ifndef LIBSECP256K1_HASH_TO_CURVE_H
#define LIBSECP256K1_HASH_TO_CURVE_H

#include "../../../include/secp256k1.h"
#include "../../../include/secp256k1_frost.h"

/*
 * The function hash_to_field hashes arbitrary-length byte strings to
 * a list of one or more elements of a finite field F;
 */
static void hash_to_field(
        /*out: */
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
 *  hash_to_curve is a uniform encoding from byte strings to points in G.
 *  That is, the distribution of its output is statistically close to uniform in G.
 */
static int hash_to_curve(
        /*out: */
        /*in: */ const unsigned char *msg, uint32_t msg_length) {

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

    return 1;
}

#endif //LIBSECP256K1_HASH_TO_CURVE_H
