#!/usr/bin/env python3
# Copyright (c) 2023 Random "Randy" Lattice and Sean Andersen
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php.
'''
Generate a C file with FROST IETF test vectors.
'''

import json
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
print("")
 
max_participants = int(doc['configuration_information']['MAX_PARTICIPANTS'])
for i in doc['configuration_information']:
    print(f"#define IETF_FROST_{i} {doc['configuration_information'][i]}")
print("")


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
print("")


print("/* Section: signer_input_parameters */")

print(f"#define IETF_FROST_PARTICIPANT_SHARE_SIZE {str(int(len(doc['signer_input_parameters']['participant_share'][0])/2))}")
print("static const unsigned char ietf_frost_participant_shares[]    = { ")
for i in doc['signer_input_parameters']['participant_share']:
     print(f"{to_c_array(i)},")
print("};")
print("")


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

hiding_nonce_randomnesses = ""
binding_nonce_randomnesses = ""
hiding_nonces = ""
binding_nonces = ""
hiding_nonce_commitments = ""
binding_nonce_commitments = ""
binding_factor_inputs = "" 
binding_factors = ""

for i in range(1, max_participants + 1):
    signer = signer_outputs.get(f"participant_{i}")
    if signer is None: 
        hiding_nonce_randomnesses += f"{ '0x0,' * len_hnr} \n"
        binding_nonce_randomnesses += f"{ '0x0,' * len_bnr} \n"
        hiding_nonces += f"{ '0x0,' * len_hn} \n"
        binding_nonces += f"{ '0x0,' * len_bn} \n"
        hiding_nonce_commitments += f"{ '0x0,' * len_hnc} \n"
        binding_nonce_commitments += f"{ '0x0,' * len_bnc} \n"
        binding_factor_inputs += f"{ '0x0,' * len_bfi} \n" 
        binding_factors += f"{ '0x0,' * len_bf} \n"
    else:
        hiding_nonce_randomnesses += f"{ to_c_array(signer['hiding_nonce_randomness'])}, \n"
        binding_nonce_randomnesses += f"{ to_c_array(signer['binding_nonce_randomness'])}, \n"
        hiding_nonces += f"{ to_c_array(signer['hiding_nonce'])}, \n"
        binding_nonces += f"{ to_c_array(signer['binding_nonce'])}, \n"
        hiding_nonce_commitments += f"{ to_c_array(signer['hiding_nonce_commitment'])}, \n"
        binding_nonce_commitments += f"{ to_c_array(signer['binding_nonce_commitment'])}, \n"
        binding_factor_inputs += f"{ to_c_array(signer['binding_factor_input'])}, \n" 
        binding_factors += f"{ to_c_array(signer['binding_factor'])}, \n"

print(f"static const unsigned char ietf_frost_hiding_nonce_randomnesses[] = {{{hiding_nonce_randomnesses}}};")
print(f"static const unsigned char ietf_frost_binding_nonce_randomnesses[] = {{{binding_nonce_randomnesses}}};")
print(f"static const unsigned char ietf_frost_hiding_nonces[] = {{{hiding_nonces}}};")
print(f"static const unsigned char ietf_frost_binding_nonces[] = {{{binding_nonces}}};")
print(f"static const unsigned char ietf_frost_hiding_nonce_commitments[] = {{{hiding_nonce_commitments}}};")
print(f"static const unsigned char ietf_frost_binding_nonce_commitments[] = {{{binding_nonce_commitments}}};")
print(f"static const unsigned char ietf_frost_binding_factor_inputs[] = {{{binding_factor_inputs}}};")
print(f"static const unsigned char ietf_frost_binding_factors[] = {{{binding_factors}}};")
print("")


print("/* Section: round_two.signer_outputs */")

signer_outputs = doc['round_two']['signer_outputs']
sig = doc['round_two']['sig']

len_sig_share = int(len(signer_outputs['participant_1']['sig_share'])/2)
print(f"#define IETF_FROST_SIG_SHARE_SIZE {str(len_sig_share)}")

len_sig  = int(len(sig)/2)
print(f"#define IETF_FROST_SIG_SIZE {str(len_sig)}")

sig_shares = ""
for i in range(1, max_participants + 1):
    signer = signer_outputs.get(f"participant_{i}")
    if signer is None: 
        sig_shares += f"{ '0x0,' * len_sig_share} \n"
    else:
        sig_shares += f"{ to_c_array(signer['sig_share'])}, \n"

print(f"static const unsigned char ietf_frost_sig_shares[] = {{{sig_shares}}};")
print(f"static const unsigned char ietf_frost_sig[] = {{{to_c_array(sig)}}};")
