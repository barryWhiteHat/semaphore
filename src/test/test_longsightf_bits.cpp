// Copyright (c) 2018 HarryR
// License: LGPL-3.0+

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

#include "gadgets/longsightf_bits.cpp"
#include "utils.hpp"
#include "ethsnarks.hpp"


using libff::convert_bit_vector_to_field_element;

using ethsnarks::ppT;
using ethsnarks::FieldT;

bool test_LongsightF_bits()
{
    typedef LongsightF_bits_gadget<FieldT,LongsightF322p5_gadget<FieldT>> HashT;

    protoboard<FieldT> pb;

    auto expected_L = FieldT("3703141493535563179657531719960160174296085208671919316200479060314459804651");
    auto expected_R = FieldT("134551314051432487569247388144051420116740427803855572138106146683954151557");
    
    digest_variable<FieldT> in_xL_digest(pb, HashT::get_digest_len(), "xL_digest");
    digest_variable<FieldT> in_xR_digest(pb, HashT::get_digest_len(), "xR_digest");
    block_variable<FieldT> in_block(pb, in_xL_digest, in_xR_digest, "in_block");
    digest_variable<FieldT> output_digest(pb, HashT::get_digest_len(), "output_digest");

    in_xL_digest.generate_r1cs_witness(convert_field_element_to_bit_vector(expected_L));
    in_xR_digest.generate_r1cs_witness(convert_field_element_to_bit_vector(expected_R));

    HashT the_gadget(pb, HashT::get_block_len(), in_block, output_digest);

    the_gadget.generate_r1cs_witness();
    the_gadget.generate_r1cs_constraints(false);

    // TODO: verify decoded bits
    if( pb.val(the_gadget.left_element) != expected_L )
    {
        std::cerr << "L mismatch!\n";
        return false;
    }

    if( pb.val(the_gadget.right_element) != expected_R )
    {
        std::cerr << "R mismatch!\n";
        return false;
    }

    auto result_expected = FieldT("1955118202659622298192442035507501123132991419752400995882287708761535290053");
    if( pb.val(the_gadget.hasher.result()) != result_expected ) {
        std::cerr << "Internal result incorrect!\n";
        return false;
    }

    auto result_actual = convert_bit_vector_to_field_element<FieldT>(the_gadget.get_digest());
    if( result_expected != result_actual ) {
        std::cerr << "Unexpected result!\n";
        return false;
    }

    std::cerr << "Constraints: " << pb.num_constraints() << "\n";

    return pb.is_satisfied();
}


int main( int argc, char **argv )
{
    // Types for board
    ppT::init_public_params();

    if( ! test_LongsightF_bits() )
    {
        std::cerr << "FAIL\n";
        return 1;
    }

    std::cout << "OK\n";
    return 0;
}
