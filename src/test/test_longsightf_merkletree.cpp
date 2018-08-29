// Copyright (c) 2018 HarryR
// License: LGPL-3.0+

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

#include <libsnark/common/data_structures/set_commitment.hpp>

#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_authentication_path_variable.hpp>
#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_read_gadget.hpp>

#include "gadgets/longsightf_bits.cpp"
#include "ethsnarks.hpp"
#include "utils.hpp"

using libsnark::set_commitment_accumulator;
using libff::convert_bit_vector_to_field_element;
using libsnark::two_to_one_CRH;
using libsnark::merkle_authentication_node;
using libsnark::merkle_authentication_path_variable;
using libsnark::merkle_tree_check_read_gadget;

using ethsnarks::ppT;
using ethsnarks::FieldT;

bool test_LongsightF_merkle_read()
{
    typedef LongsightF_bits_gadget<FieldT, LongsightF322p5_gadget<FieldT>> HashT;

    protoboard<FieldT> pb;

    auto item_A = FieldT("3703141493535563179657531719960160174296085208671919316200479060314459804651");
    digest_variable<FieldT> digest_A(pb, HashT::get_digest_len(), "digest_A");
    digest_A.generate_r1cs_witness(convert_field_element_to_bit_vector(item_A));

    auto item_B = FieldT("134551314051432487569247388144051420116740427803855572138106146683954151557");
    digest_variable<FieldT> digest_B(pb, HashT::get_digest_len(), "digest_B");
    digest_B.generate_r1cs_witness(convert_field_element_to_bit_vector(item_B));

    auto result_expected = FieldT("1955118202659622298192442035507501123132991419752400995882287708761535290053");
    digest_variable<FieldT> digest_expected(pb, HashT::get_digest_len(), "digest_expected");
    digest_expected.generate_r1cs_witness(convert_field_element_to_bit_vector(result_expected));

    pb_variable<FieldT> zero;
    zero.allocate(pb);
    pb.val(zero) = FieldT::zero();

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
            zero,               // copy result to output
            "read_gadget" );

    path_var.generate_r1cs_constraints();
    read_gadget.generate_r1cs_constraints();

    address_bits_var.fill_with_bits(pb, {0});
    path_var.generate_r1cs_witness(0, path);
    read_gadget.generate_r1cs_witness();

    return pb.is_satisfied();
}


int main( int argc, char **argv )
{
    // Types for board
    ppT::init_public_params();

    if( ! test_LongsightF_merkle_read() )
    {
        std::cerr << "FAIL merkle read\n";
        return 1;
    }

    std::cout << "OK\n";
    return 0;
}
