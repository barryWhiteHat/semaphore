// Copyright (c) 2018 HarryR
// License: LGPL-3.0+

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>

#include <libsnark/common/data_structures/set_commitment.hpp>

#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_authentication_path_variable.hpp>
#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_read_gadget.hpp>

#include "gadgets/longsightf_bits.cpp"
#include "utils.cpp"

using libsnark::set_commitment_accumulator;
using libff::convert_bit_vector_to_field_element;
using libsnark::two_to_one_CRH;
using libsnark::merkle_authentication_node;
using libsnark::merkle_authentication_path_variable;
using libsnark::merkle_tree_check_read_gadget;

template<typename ppT>
bool test_LongsightF_merkle_read()
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

    auto tto_result = two_to_one_CRH<HashT>(digest_A.get_digest(), digest_B.get_digest());
    if( tto_result != digest_expected.get_digest() ) {
        std::cerr << "merkle_tree two_to_one_CRH mismatch!\n";
        return false;
    }

    std::vector<merkle_authentication_node> path { digest_B.get_digest() };
    size_t tree_depth = 1;
    
    pb_variable_array<FieldT> address_bits_var;
    address_bits_var.allocate(pb, tree_depth, "address_bits");
    merkle_authentication_path_variable<FieldT, HashT> path_var(pb, tree_depth, "path");
    merkle_tree_check_read_gadget<FieldT,HashT> read_gadget(
            pb,
            tree_depth,
            address_bits_var,
            digest_A,           // leaf_digest
            digest_expected,    // root_digest
            path_var,
            ONE,
            "read_gadget" );

    path_var.generate_r1cs_constraints();
    read_gadget.generate_r1cs_constraints();

    address_bits_var.fill_with_bits(pb, {0});
    read_gadget.generate_r1cs_witness();


    // TODO: generate constraints

    // TODO: generate witness
    return pb.is_satisfied()    ;
}


template<typename ppT>
bool test_LongsightF_set_commitment()
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

    auto tto_result = two_to_one_CRH<HashT>(digest_A.get_digest(), digest_B.get_digest());
    if( tto_result != digest_expected.get_digest() ) {
        std::cerr << "merkle_tree two_to_one_CRH mismatch!\n";
        return false;
    }

    print_bv("digest A", digest_A.get_digest());
    print_bv("digest B", digest_B.get_digest());

    set_commitment_accumulator<HashT> accumulator(2, HashT::get_digest_len());

    accumulator.add(digest_A.get_digest());
    accumulator.add(digest_B.get_digest());

    // TODO: verify known values
    // Root should be H(A,B)
    // Path A should be B
    // Path B should be A
    // Path A != Path B
    print_bv("root", accumulator.get_commitment());
    print_bv("\nexpected root", digest_expected.get_digest());

    std::cout << "\n";
    auto proof_A = accumulator.get_membership_proof(digest_A.get_digest());
    int i = 0;
    std::cout << "addr A " << proof_A.address << "\n";
    for( auto& node : proof_A.merkle_path ) {
        std::cout << i << " ";
        print_bv("A", node);
    }

    std::cout << "\n";
    auto proof_B = accumulator.get_membership_proof(digest_B.get_digest());
    i = 0;
    std::cout << "addr B " << proof_B.address << "\n";
    for( auto& node : proof_A.merkle_path ) {
        std::cout << i << " ";
        print_bv("B", node);
    }

    return pb.is_satisfied();
}


int main( int argc, char **argv )
{
    // Types for board
    typedef libff::alt_bn128_pp ppT;    
    ppT::init_public_params();

    if( ! test_LongsightF_merkle_read<ppT>() )
    {
        std::cerr << "FAIL merkle read\n";
        return 1;
    }

    if( ! test_LongsightF_set_commitment<ppT>() )
    {
        std::cerr << "FAIL set commitment\n";
        return 1;
    }

    std::cout << "OK\n";
    return 0;
}
