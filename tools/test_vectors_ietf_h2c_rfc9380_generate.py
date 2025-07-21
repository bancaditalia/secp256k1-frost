#!/usr/bin/env python3
# Copyright (c) 2023 Bank of Italy
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php.

"""
Generate a C file with the Hash-to-curve IETF test vectors (RFC 9380).

Usage:
> python tools/test_vectors_ietf_h2c_rfc9380_generate.py \
    src/modules/frost/vectors/ietf_h2c_rfc9380_ro_test_vectors.json \
    src/modules/frost/vectors/ietf_h2c_rfc9380_nu_test_vectors.json \
    > src/modules/frost/vectors/ietf_h2c_rfc9380_test_vectors.h
"""

import json
import sys


def to_c_array(x):
    if x == "": return ""
    s = ',0x'.join(a+b for a,b in zip(x[::2], x[1::2]))
    return "0x" + s


def parse_and_translate_common_data():
    print("""
typedef struct {
    size_t msg_offset;
    size_t msg_len;
} ietf_rfc9380_test_vector;""")
    print("")


def parse_and_translate_test_vectors(filename: str, encoding: str):
    with open(filename) as f:
        doc = json.load(f)
    num_vectors = len(doc['vectors'])
    string_as_char_array = ','.join(f"'{c}'" for c in doc['dst'])
    print("/* ****** ****** ****** ****** ****** ****** ****** ****** ****** ******  */")
    print(f"/*   Suite: {doc['suite']} */")
    print(f"/*   Reference: {doc['url']} */")
    print(f"/*   Encoding: {encoding} */")
    print("/* ****** ****** ****** ****** ****** ****** ****** ****** ****** ******  */")
    print("")
    print(f"#define IETF_RFC9380_{encoding.upper()}_TEST_VECTORS {int(num_vectors)}")
    print(f"#define IETF_RFC9380_{encoding.upper()}_DST_LEN {len(doc['dst'])}")
    print("")
    print(f"static const unsigned char ietf_rfc9380_{encoding.lower()}_dst[IETF_RFC9380_{encoding.upper()}_DST_LEN] = {{ {string_as_char_array} }};")
    print("")

    offset_msg_running = 0
    msgs = ""
    Px = ""
    Py = ""
    u0 = ""
    u1 = ""
    q0x = ""
    q0y = ""
    q1x = ""
    q1y = ""
    out = ""

    len_Px = 0
    len_Py = 0
    len_u0 = 0
    len_u1 = 0
    len_q0x = 0
    len_q0y = 0
    len_q1x = 0
    len_q1y = 0

    for i in range(num_vectors):
        vector = doc['vectors'][i]
        if len_Px == 0:
            len_Px = int(len(vector['P.x']) / 2)
        if len_Py == 0:
            len_Py = int(len(vector['P.y']) / 2)
        if len_u0 == 0:
            len_u0 = int(len(vector['u[0]']) / 2)
        if encoding.lower() == "ro":
            if len_u1 == 0:
                len_u1 = int(len(vector['u[1]']) / 2)
            if len_q0x == 0:
                len_q0x = int(len(vector['Q0.x']) / 2)
            if len_q0y == 0:
                len_q0y = int(len(vector['Q0.y']) / 2)
            if len_q1x == 0:
                len_q1x = int(len(vector['Q1.x']) / 2)
            if len_q1y == 0:
                len_q1y = int(len(vector['Q1.y']) / 2)
        else:
            if len_q0x == 0:
                len_q0x = int(len(vector['Q.x']) / 2)
            if len_q0y == 0:
                len_q0y = int(len(vector['Q.y']) / 2)

        Px += f"{ to_c_array(vector['P.x'])}, \n"
        Py += f"{ to_c_array(vector['P.y'])}, \n"
        u0 += f"{ to_c_array(vector['u[0]'])}, \n"
        if encoding.lower() == "ro":
            u1 += f"{ to_c_array(vector['u[1]'])}, \n"
            q0x += f"{ to_c_array(vector['Q0.x'])}, \n"
            q0y += f"{ to_c_array(vector['Q0.y'])}, \n"
            q1x += f"{ to_c_array(vector['Q1.x'])}, \n"
            q1y += f"{ to_c_array(vector['Q1.y'])}, \n"
        else:
            q0x += f"{ to_c_array(vector['Q.x'])}, \n"
            q0y += f"{ to_c_array(vector['Q.y'])}, \n"

        msg_len = len(vector['msg'])
        msg_offset = offset_msg_running

        if msg_len > 0:
            msgs += f"{ to_c_array(vector['msg'].encode('utf-8').hex())}, \n"

        out += f"  {{{msg_offset}, {msg_len} }},\n"
        offset_msg_running += msg_len

    print(f"#define IETF_RFC9380_{encoding.upper()}_Px_SIZE {str(len_Px)}")
    print(f"#define IETF_RFC9380_{encoding.upper()}_Py_SIZE {str(len_Py)}")
    print(f"#define IETF_RFC9380_{encoding.upper()}_u0_SIZE {str(len_u0)}")
    if encoding.lower() == "ro":
        print(f"#define IETF_RFC9380_{encoding.upper()}_u1_SIZE {str(len_u1)}")
        print(f"#define IETF_RFC9380_{encoding.upper()}_Q0x_SIZE {str(len_q0x)}")
        print(f"#define IETF_RFC9380_{encoding.upper()}_Q0y_SIZE {str(len_q0y)}")
        print(f"#define IETF_RFC9380_{encoding.upper()}_Q1x_SIZE {str(len_q1x)}")
        print(f"#define IETF_RFC9380_{encoding.upper()}_Q1y_SIZE {str(len_q1y)}")
    else:
        print(f"#define IETF_RFC9380_{encoding.upper()}_Qx_SIZE {str(len_q0x)}")
        print(f"#define IETF_RFC9380_{encoding.upper()}_Qy_SIZE {str(len_q0y)}")
    print("")

    print(f"static const unsigned char ietf_rfc9380_{encoding.lower()}_pxs[] = {{{Px}}};")
    print(f"static const unsigned char ietf_rfc9380_{encoding.lower()}_pys[] = {{{Py}}};")
    print(f"static const unsigned char ietf_rfc9380_{encoding.lower()}_u0s[] = {{{u0}}};")
    if encoding.lower() == "ro":
        print(f"static const unsigned char ietf_rfc9380_{encoding.lower()}_u1s[] = {{{u1}}};")
        print(f"static const unsigned char ietf_rfc9380_{encoding.lower()}_q0xs[] = {{{q0x}}};")
        print(f"static const unsigned char ietf_rfc9380_{encoding.lower()}_q0ys[] = {{{q0y}}};")
        print(f"static const unsigned char ietf_rfc9380_{encoding.lower()}_q1xs[] = {{{q1x}}};")
        print(f"static const unsigned char ietf_rfc9380_{encoding.lower()}_q1ys[] = {{{q1y}}};")
    else:
        print(f"static const unsigned char ietf_rfc9380_{encoding.lower()}_qxs[] = {{{q0x}}};")
        print(f"static const unsigned char ietf_rfc9380_{encoding.lower()}_qys[] = {{{q0y}}};")

    print("")
    print(f"static const unsigned char ietf_rfc9380_{encoding.lower()}_messages[] = {{ {msgs} }};")
    print("")
    print(f"static const ietf_rfc9380_test_vector ietf_rfc9380_{encoding.lower()}_test_vectors[IETF_RFC9380_{encoding.upper()}_TEST_VECTORS] = {{")
    print(out)
    print("};")
    print("/* ****** ****** ****** ****** ****** ****** ****** ****** ****** ******  */")
    print("")


if __name__ == "__main__":
    print("/* Note: this file was autogenerated using test_vectors_ietf_h2c_rfc9380_generate.py. Do not edit. */")

    if len(sys.argv) < 3:
        print("Script called with the wrong number of parameters.")
        print(" Two parameters expected: \n"
              " - ietf_h2c_rfc9380_ro_test_vectors.json \n" 
              " - ietf_h2c_rfc9380_nu_test_vectors.json")
        exit(1)

    ro_input = sys.argv[1]
    nu_input = sys.argv[2]

    parse_and_translate_common_data()
    parse_and_translate_test_vectors(ro_input, "ro")
    parse_and_translate_test_vectors(nu_input, "nu")
