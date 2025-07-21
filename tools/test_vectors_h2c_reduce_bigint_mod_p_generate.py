from typing import Iterator, Tuple

SECP256K1_P = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)


def bigint_to_limbs(x: int) -> Tuple[int, ...]:
    """Return x as a tuple of uint64_t limbs (little-endian)."""
    limbs = []
    while x > 0:
        limbs.append(x & 0xFFFFFFFFFFFFFFFF)
        x >>= 64
    return tuple(limbs or [0])


def int_to_be_bytes(x: int) -> bytes:
    """Convert integer x to a 32-byte big-endian array."""
    return x.to_bytes(32, 'big')


def reduce_bigint_mod_p_tests() -> Iterator[Tuple[str, Tuple[int, ...], bytes]]:
    """Generate test cases for reduce_bigint_mod_p function."""
    tests = [
        ("a = 0", 0),
        ("a = 1", 1),
        ("a = p - 1", SECP256K1_P - 1),
        ("a = p", SECP256K1_P),
        ("a = p + 1", SECP256K1_P + 1),
        ("a = 2 * p", 2 * SECP256K1_P),
        # Additional edge cases
        ("a = p - 2", SECP256K1_P - 2),
        ("a = p + 2", SECP256K1_P + 2),
        ("a = 3 * p", 3 * SECP256K1_P),
        ("a = p^2 mod p (should be 0)", SECP256K1_P * SECP256K1_P),
        # Large number that requires multiple reduction steps
        ("a = 2^384 - 1", (1 << 384) - 1),
        # Random 48-byte value (typical for hash-to-field)
        ("a = random 48-byte", int("123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", 16)),
    ]

    for name, val in tests:
        limbs = bigint_to_limbs(val)
        reduced = val % SECP256K1_P
        output = int_to_be_bytes(reduced)
        yield name, limbs, output


def verify_test_case(name: str, limbs: Tuple[int, ...], expected_output: bytes) -> bool:
    """Verify that a test case is mathematically correct."""
    # Reconstruct the original value from limbs
    original_value = sum(limb << (64 * i) for i, limb in enumerate(limbs))

    # Compute expected reduction
    expected_reduced = original_value % SECP256K1_P
    expected_bytes = int_to_be_bytes(expected_reduced)

    # Verify
    if expected_bytes != expected_output:
        print(f"ERROR in {name}:")
        print(f"  Original: {hex(original_value)}")
        print(f"  Expected reduced: {hex(expected_reduced)}")
        print(f"  Generated output: {expected_output.hex()}")
        print(f"  Computed output:  {expected_bytes.hex()}")
        return False

    return True


def format_c_limbs(limbs: Tuple[int, ...]) -> str:
    """Format limbs as C array initializer."""
    if len(limbs) <= 4:
        # Short format for small arrays
        return "{" + ', '.join(f"0x{l:016x}" for l in limbs) + "}"
    else:
        # Multi-line format for large arrays
        formatted = "{\n    "
        for i, limb in enumerate(limbs):
            if i > 0 and i % 4 == 0:
                formatted += ",\n    "
            elif i > 0:
                formatted += ", "
            formatted += f"0x{limb:016x}"
        formatted += "\n  }"
        return formatted


def format_c_bytes(output: bytes) -> str:
    """Format bytes as C array initializer."""
    formatted = "{\n    "
    for i, byte in enumerate(output):
        if i > 0 and i % 12 == 0:
            formatted += ",\n    "
        elif i > 0:
            formatted += ", "
        formatted += f"0x{byte:02x}"
    formatted += "\n  }"
    return formatted


if __name__ == "__main__":
    print("/* Generated test vectors for reduce_bigint_mod_p() */")
    print(f"/* SECP256K1_P = 0x{SECP256K1_P:064x} */\n")

    index = 0
    all_tests_valid = True

    for name, limbs, output in reduce_bigint_mod_p_tests():
        # Verify test case
        if not verify_test_case(name, limbs, output):
            all_tests_valid = False
            continue

        print(f"/* {name} */")
        print(f"bigint_internal a{index} = {{")
        print(f"  {format_c_limbs(limbs)},")
        print(f"  {len(limbs)}")
        print("};")
        print(f"unsigned char expected{index}[32] = {format_c_bytes(output)};")
        print()
        index += 1

    if all_tests_valid:
        print(f"/* All {index} test cases verified successfully */")
    else:
        print("/* WARNING: Some test cases failed verification */")

    # Generate test function
    print(f"""
static void test_reduce_bigint_mod_p(void) {{
    unsigned char result[32];
    int tests_passed = 0;
    int total_tests = {index};
    
    bigint_internal* test_inputs[] = {{{', '.join(f'&a{i}' for i in range(index))}}};
    unsigned char* expected_outputs[] = {{{', '.join(f'expected{i}' for i in range(index))}}};
    const char* test_names[] = {{{', '.join(f'"{name}"' for name, _, _ in reduce_bigint_mod_p_tests())}}};
    
    for (int i = 0; i < total_tests; i++) {{
        reduce_bigint_mod_p(result, test_inputs[i]);
        
        if (memcmp(result, expected_outputs[i], 32) == 0) {{
            printf("Test %d (%s): PASSED\\n", i, test_names[i]);
            tests_passed++;
        }} else {{
            printf("Test %d (%s): FAILED\\n", i, test_names[i]);
            printf("  Expected: ");
            for (int j = 0; j < 32; j++) printf("%02x", expected_outputs[i][j]);
            printf("\\n  Got:      ");
            for (int j = 0; j < 32; j++) printf("%02x", result[j]);
            printf("\\n");
        }}
    }}
    
    printf("\\nResults: %d/%d tests passed\\n", tests_passed, total_tests);
    if (tests_passed == total_tests) {{
        printf("All tests PASSED!\\n");
    }} else {{
        printf("Some tests FAILED!\\n");
    }}
}}""")