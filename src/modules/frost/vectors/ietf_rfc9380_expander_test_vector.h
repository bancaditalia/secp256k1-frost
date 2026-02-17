#ifndef IETF_RFC9380_EXPANDER_TEST_VECTOR_H
#define IETF_RFC9380_EXPANDER_TEST_VECTOR_H

#include <stddef.h>

typedef struct {
    size_t len_in_bytes;
    size_t msg_offset;
    size_t msg_len;
    size_t msg_prime_offset;
    size_t msg_prime_len;
    size_t uniform_bytes_offset;
} ietf_rfc9380_expander_test_vector;

#endif /* IETF_RFC9380_EXPANDER_TEST_VECTOR_H */
