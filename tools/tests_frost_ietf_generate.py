#!/usr/bin/env python3
# Copyright (c) 2023 Random "Randy" Lattice and Sean Andersen
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php.
'''
Generate a C file with FROST IETF test vectors.
'''

import json
import hashlib
import urllib.request
import sys

filename_input = sys.argv[1]

with open(filename_input) as f:
    doc = json.load(f)

def to_c_array(x):
    if x == "": return ""
    s = ',0x'.join(a+b for a,b in zip(x[::2], x[1::2]))
    return "0x" + s


num_vectors = 0
offset_msg_running, offset_pk_running, offset_sig = 0, 0, 0
out = ""
messages = ""
signatures = ""
public_keys = ""
cache_msgs = {}
cache_public_keys = {}

print("/* Note: this file was autogenerated using tests_frost_ietf_generate.py. Do not edit. */")

for i in doc['configuration_information']:
    print(f"#define IETF_FROST_{i} {doc['configuration_information'][i]}")
print("\n")

print("/* Section: group_input_parameters */")

participant_list = ", ".join([str(x) for x in doc['group_input_parameters']['participant_list']])
print(f"static const uint32_t ietf_frost_participants[]      = {{{participant_list}}};")

print("static const unsigned char ietf_frost_group_secret_key[]    = { " +
      to_c_array(doc['group_input_parameters']['group_secret_key']) + "};")
print("static const unsigned char ietf_frost_group_public_key[]    = { " +
      to_c_array(doc['group_input_parameters']['group_public_key']) + "};")

print("static const unsigned char ietf_frost_message[]    = { " +
      to_c_array(doc['group_input_parameters']['message']) + "};")
print(f"static const size_t ietf_frost_message_length      = {str(len(doc['group_input_parameters']['message']))};")

# TODO: improve representation of coefficients (threshold - 1)
print("static const unsigned char ietf_frost_share_polynomial_coefficients_0[]  = { " +
      to_c_array(doc['group_input_parameters']['share_polynomial_coefficients'][0]) + "};")

