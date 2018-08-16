// Copyright (c) 2018 HarryR
// License: LGPL-3.0+

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>

#include <libsnark/common/data_structures/set_commitment.hpp>

#include "gadgets/longsightf_bits.cpp"
#include "utils.cpp"

using libsnark::set_commitment_accumulator;
using libff::convert_bit_vector_to_field_element;


template<typename ppT>
bool test_LongsightF_merkletree()
{
    typedef libff::Fr<ppT> FieldT;
    typedef LongsightF_bits_gadget<FieldT, LongsightF152p5_gadget<FieldT>> HashT;

    protoboard<FieldT> pb;

    auto item_A = FieldT("21871881226116355513319084168586976250335411806112527735069209751513595455673");
    digest_variable<FieldT> digest_A(pb, HashT::get_digest_len(), "digest_A");
    digest_A.generate_r1cs_witness(convert_field_element_to_bit_vector(item_A));

    auto item_B = FieldT("55049861378429053168722197095693172831329974911537953231866155060049976290");
    digest_variable<FieldT> digest_B(pb, HashT::get_digest_len(), "digest_B");
    digest_B.generate_r1cs_witness(convert_field_element_to_bit_vector(item_B));

    auto result_expected = FieldT("11801552584949094581972187388927133931539817817986253233814495442311083852545");
    digest_variable<FieldT> digest_expected(pb, HashT::get_digest_len(), "digest_expected");
    digest_expected.generate_r1cs_witness(convert_field_element_to_bit_vector(result_expected));

    print_bv("digest A", digest_A.get_digest());
    print_bv("digest B", digest_B.get_digest());

    set_commitment_accumulator<HashT> accumulator(2, HashT::get_digest_len());
    accumulator.add(digest_A.get_digest());
    accumulator.add(digest_B.get_digest());

    print_bv("root", accumulator.get_commitment());
    print_bv("expected root", digest_expected.get_digest());
    //std::cerr << "proof A " << accumulator.get_membership_proof(digest_A.get_digest()) << "\n";
    //std::cerr << "proof B " << accumulator.get_membership_proof(digest_B.get_digest()) << "\n";

    return pb.is_satisfied();
}


int main( int argc, char **argv )
{
    // Types for board
    typedef libff::alt_bn128_pp ppT;    
    ppT::init_public_params();

    if( ! test_LongsightF_merkletree<ppT>() )
    {
        std::cerr << "FAIL\n";
        return 1;
    }

    std::cout << "OK\n";
    return 0;
}
