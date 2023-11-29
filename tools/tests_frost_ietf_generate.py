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

print("\n")
print("/* Section: signer_input_parameters */")

print(f"#define IETF_FROST_PARTICIPANT_SHARE_SIZE {str(int(len(doc['signer_input_parameters']['participant_share'][0])/2))}")
print("static const unsigned char ietf_frost_participant_shares[]    = { ");
for i in doc['signer_input_parameters']['participant_share']:
     print(f"{to_c_array(i)},")
print("};\n")

print("\n")
print("/* Section: round_one.signer_outputs */")

signer_outputs = doc['round_one']['signer_outputs']
len_hnr = int(len(signer_outputs['participant_1']['hiding_nonce_randomness'])/2)
len_hn  = int(len(signer_outputs['participant_1']['hiding_nonce'])/2)
len_bnr  = int(len(signer_outputs['participant_1']['binding_nonce_randomness'])/2)
len_bn  = int(len(signer_outputs['participant_1']['binding_nonce'])/2)
len_hnc  = int(len(signer_outputs['participant_1']['hiding_nonce_commitment'])/2)
len_bnc  = int(len(signer_outputs['participant_1']['binding_nonce_commitment'])/2)
len_bfi  = int(len(signer_outputs['participant_1']['binding_factor_input'])/2)
len_bf  = int(len(signer_outputs['participant_1']['binding_factor'])/2)

print(f"#define IETF_FROST_HIDING_NONCE_RANDOMNESS_SIZE {str(len_hnr)}")
print(f"#define IETF_FROST_HIDING_NONCE_SIZE {str(len_hn)}")
print(f"#define IETF_FROST_BINDING_NONCE_RANDOMNESS_SIZE {str(len_bnr)}")
print(f"#define IETF_FROST_BINDING_NONCE_SIZE {str(len_bn)}")
print(f"#define IETF_FROST_HIDING_NONCE_COMMITMENT_SIZE {str(len_hnc)}")
print(f"#define IETF_FROST_BINDING_NONCE_COMMITMENT_SIZE {str(len_bnc)}")
print(f"#define IETF_FROST_BINDING_FACTOR_INPUT_SIZE {str(len_bfi)}")
print(f"#define IETF_FROST_BINDING_FACTOR_SIZE {str(len_bf)}")


