#ifndef SECP256K1_MODULE_FROST_BIGINT_H
#define SECP256K1_MODULE_FROST_BIGINT_H

#define BIGINT_MAX_LIMBS 8
#define BIGINT_BITS_PER_LIMB 64
#define BIGINT_BYTES_256 32
#define BIGINT_LIMBS_256 4
#define BIGINT_BYTES_PER_LIMB 8
#define BIGINT_MSB_MASK 0x8000000000000000ULL
#define BIGINT_REPEATED_SUB_THRESHOLD 10

typedef struct {
  uint64_t limbs[BIGINT_MAX_LIMBS];
  /* little-endian: limbs[0] = least significant */
  size_t nlimbs;
} bigint_internal;

static int bigint_is_valid(const bigint_internal *a) {
    if (a == NULL) return 0;
    if (a->nlimbs == 0 || a->nlimbs > BIGINT_MAX_LIMBS) return 0;
    /* Ensure proper normalization */
    if (a->nlimbs > 1 && a->limbs[a->nlimbs - 1] == 0) return 0;
    return 1;
}

/* Helper function to compare two bigints */
/* Returns: -1 if a < b, 0 if a == b, 1 if a > b */
static int bigint_compare(const bigint_internal *a, const bigint_internal *b) {
    int i;

    /* Different number of limbs means different values */
    if (a->nlimbs != b->nlimbs) {
        return (a->nlimbs > b->nlimbs) ? 1 : -1;
    }

    /* Same number of limbs, compare from the most significant */
    for (i = (int)a->nlimbs - 1; i >= 0; i--) {
        if (a->limbs[i] != b->limbs[i]) {
            return (a->limbs[i] > b->limbs[i]) ? 1 : -1;
        }
    }

    return 0;
}

/* Helper function to subtract b from a (requires a >= b) */
/* Returns: 0 on success, -1 on error */
static int bigint_subtract(bigint_internal *result, const bigint_internal *a, const bigint_internal *b) {
    uint64_t borrow = 0;
    size_t i;
    int cmp;

    /* Input validation */
    if (result == NULL) {
        return -1;
    }

    /* Verify a >= b to prevent underflow */
    cmp = bigint_compare(a, b);
    if (cmp < 0) {
        return -1; /* Cannot subtract larger from smaller */
    }

    /* Process all limbs of a */
    for (i = 0; i < a->nlimbs; i++) {
        uint64_t a_val = a->limbs[i];
        uint64_t b_val = (i < b->nlimbs) ? b->limbs[i] : 0;

        /* Check if we need to borrow - avoid overflow */
        int need_borrow;
        if (borrow == 0) {
            need_borrow = (a_val < b_val);
        } else {
            need_borrow = (a_val <= b_val);
        }
        result->limbs[i] = a_val - b_val - borrow;
        borrow = need_borrow != 0;
    }

    /* Set the number of limbs and remove leading zeros */
    result->nlimbs = a->nlimbs;
    while (result->nlimbs > 1 && result->limbs[result->nlimbs - 1] == 0) {
        result->nlimbs--;
    }

    /* Clear unused limbs */
    for (i = result->nlimbs; i < BIGINT_MAX_LIMBS; i++) {
        result->limbs[i] = 0;
    }

    return 0;
}

/* Helper function to copy a bigint_internal */
static void bigint_copy(bigint_internal *dest, const bigint_internal *src) {
    size_t i;

    dest->nlimbs = src->nlimbs;
    for (i = 0; i < src->nlimbs; i++) {
        dest->limbs[i] = src->limbs[i];
    }
    /* Clear remaining limbs */
    for (i = src->nlimbs; i < BIGINT_MAX_LIMBS; i++) {
        dest->limbs[i] = 0;
    }
}

/* Helper function to check if a bigint_internal is zero */
/* Returns: 1 if zero, 0 if non-zero */
static int bigint_is_zero(const bigint_internal *a) {
    return (a->nlimbs == 1 && a->limbs[0] == 0) ? 1 : 0;
}

/* Helper function to left shift a bigint_internal by one bit */
/* Returns: 0 on success, -1 on error or overflow */
static int bigint_left_shift(bigint_internal *a) {
    uint64_t carry = 0;
    size_t i;

    for (i = 0; i < a->nlimbs; i++) {
        uint64_t new_carry = (a->limbs[i] >> (BIGINT_BITS_PER_LIMB - 1)) & 1;
        a->limbs[i] = (a->limbs[i] << 1) | carry;
        carry = new_carry;
    }

    /* If there's a carry, and we have space, add a new limb */
    if (carry) {
        if (a->nlimbs >= BIGINT_MAX_LIMBS) {
            return -1; /* Overflow */
        }
        a->limbs[a->nlimbs] = carry;
        a->nlimbs++;
    }
    return 0;
}

/* Helper function to right shift a bigint_internal by one bit */
/* Returns: 0 on success, -1 on error */
static int bigint_right_shift(bigint_internal *a) {
    uint64_t carry = 0;
    int i;

    if (bigint_is_valid(a) == 0) {
        return -1;
    }

    for (i = (int)a->nlimbs - 1; i >= 0; i--) {
        uint64_t new_carry = (a->limbs[i] & 1) ? BIGINT_MSB_MASK : 0;
        a->limbs[i] = (a->limbs[i] >> 1) | carry;
        carry = new_carry;
    }

    /* Normalize after shift */
    while (a->nlimbs > 1 && a->limbs[a->nlimbs - 1] == 0) {
        a->nlimbs--;
    }

    return 0;
}

/* Helper function to get the bit length of a bigint_internal */
static int bigint_bit_length(const bigint_internal *a) {
    int i, j;
    uint64_t limb;

    if (bigint_is_zero(a) == 1) {
        return 0;
    }

    /* Find the most significant limb */
    for (i = (int) a->nlimbs - 1; i >= 0; i--) {
        if (a->limbs[i] != 0) {
            break;
        }
    }

    /* Find the most significant bit in that limb */
    limb = a->limbs[i];
    for (j = BIGINT_BITS_PER_LIMB - 1; j >= 0; j--) {
        if (limb & (1ULL << j)) {
            break;
        }
    }

    return i * BIGINT_BITS_PER_LIMB + j + 1;
}

/* Modulus function: r = a mod b */
/* Returns 0 on success, -1 on error (division by zero, or invalid input) */
static int bigint_mod(bigint_internal *r, const bigint_internal *a, const bigint_internal *b) {
    bigint_internal remainder, divisor, temp;
    int a_bits, b_bits, shift;
    int i, cmp;
    int remainder_vs_b_cmp, remainder_vs_divisor_cmp, divisor_vs_b_cmp;

    /* Input validation */
    if (r == NULL || bigint_is_valid(a) == 0 || bigint_is_valid(b) == 0) {
        return -1;
    }

    /* Check for division by zero */
    if (bigint_is_zero(b) == 1) {
        return -1;
    }

    /* If a < b, then a mod b = a */
    cmp = bigint_compare(a, b);
    if (cmp < 0) {
        bigint_copy(r, a);
        return 0;
    }

    /* If a == b, then a mod b = 0 */
    if (cmp == 0) {
        r->nlimbs = 1;
        r->limbs[0] = 0;
        for (i = 1; i < BIGINT_MAX_LIMBS; i++) {
            r->limbs[i] = 0;
        }
        return 0;
    }

    /* Calculate bit lengths */
    a_bits = bigint_bit_length(a);
    b_bits = bigint_bit_length(b);
    if (a_bits == -1 || b_bits == -1) {
        return -1; /* Error from bigint_bit_length */
    }

    /* Set the remainder as "a" */
    bigint_copy(&remainder, a);

    /* If the difference in bit lengths is small, use repeated subtraction */
    if (a_bits - b_bits <= BIGINT_REPEATED_SUB_THRESHOLD) {
        /* We know that remainder >= b from the initial comparison */
        remainder_vs_b_cmp = 1; /* remainder > b initially */

        while (remainder_vs_b_cmp >= 0) {
            if (bigint_subtract(&temp, &remainder, b) != 0) {
                return -1;
            }
            bigint_copy(&remainder, &temp);
            remainder_vs_b_cmp = bigint_compare(&remainder, b);
        }
        bigint_copy(r, &remainder);
        return 0;
    }

    /* Use binary long division for efficiency */
    /* Align divisor with the most significant bits of the remainder */
    bigint_copy(&divisor, b);
    shift = a_bits - b_bits;

    /* Left shift divisor to align with the remainder */
    for (i = 0; i < shift; i++) {
        if (bigint_left_shift(&divisor) != 0) {
            return -1; /* Overflow */
        }
    }

    /* Check if we shifted too far and adjust once if needed */
    remainder_vs_divisor_cmp = bigint_compare(&remainder, &divisor);
    if (remainder_vs_divisor_cmp < 0) {
        /* We shifted too far, shift divisor back one */
        if (bigint_right_shift(&divisor) != 0) {
            return -1;
        }
        /* Update comparison result after right shift */
        remainder_vs_divisor_cmp = bigint_compare(&remainder, &divisor);
    }

    /* Perform the long division - we know the remainder >= b initially */
    remainder_vs_b_cmp = 1; /* We established this earlier */
    while (remainder_vs_b_cmp >= 0) {
        if (remainder_vs_divisor_cmp >= 0) {
            if (bigint_subtract(&temp, &remainder, &divisor) != 0) {
                return -1;
            }
            bigint_copy(&remainder, &temp);
        }

        /* Right shift divisor by one bit */
        if (bigint_right_shift(&divisor) != 0) {
            return -1;
        }

        /* Check if divisor became smaller than b */
        divisor_vs_b_cmp = bigint_compare(&divisor, b);
        if (divisor_vs_b_cmp < 0) {
            /* Divisor is now smaller than b, use repeated subtraction for final steps */
            remainder_vs_b_cmp = bigint_compare(&remainder, b);
            while (remainder_vs_b_cmp >= 0) {
                if (bigint_subtract(&temp, &remainder, b) != 0) {
                    return -1;
                }
                bigint_copy(&remainder, &temp);
                remainder_vs_b_cmp = bigint_compare(&remainder, b);
            }
            break;
        }

        /* Update comparison results for next iteration */
        remainder_vs_b_cmp = bigint_compare(&remainder, b);
        remainder_vs_divisor_cmp = bigint_compare(&remainder, &divisor);
    }

    bigint_copy(r, &remainder);
    return 0;
}

/* Convert "a" bigint_internal to a 32-byte big-endian unsigned char array */
/* Returns: 0 on success, -1 on error */
static int bigint_to_bytes_be(unsigned char bytes[32], const bigint_internal *a) {
    size_t i, j;
    size_t byte_idx;
    uint64_t limb;

    /* Input validation */
    if (bytes == NULL || bigint_is_valid(a) == 0) {
        return -1;
    }

    /* Check if the number fits in 256 bits (4 limbs max) */
    if (a->nlimbs > BIGINT_LIMBS_256) {
        return -1; /* Number too large for 256-bit output */
    }

    /* Initialize output array to zero */
    for (i = 0; i < BIGINT_BYTES_256; i++) {
        bytes[i] = 0;
    }

    /* Convert each limb to bytes in big-endian format */
    for (i = 0; i < a->nlimbs; i++) {
        limb = a->limbs[i];

        /* Each limb contributes 8 bytes */
        /* limb i maps to bytes [32 - 8*(i+1)] to [32 - 8*i - 1] */
        byte_idx = BIGINT_BYTES_256 - BIGINT_BYTES_PER_LIMB * (i + 1);

        /* Extract bytes from limb in big-endian order */
        for (j = 0; j < BIGINT_BYTES_PER_LIMB; j++) {
            bytes[byte_idx + (BIGINT_BYTES_PER_LIMB - 1 - j)] = (unsigned char)((limb >> (8 * j)) & 0xFF);
        }
    }

    return 0;
}

#endif /* SECP256K1_MODULE_FROST_BIGINT_H */
