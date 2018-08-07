// Copyright (c) 2018 HarryR
// License: LGPL-3.0+

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>

#include "gadgets/one_of_n.cpp"


using libsnark::r1cs_ppzksnark_generator;
using libsnark::r1cs_ppzksnark_prover;


template<typename ppT>
bool test_one_of_n()
{
    typedef libff::Fr<ppT> FieldT;

    protoboard<FieldT> pb;

    const std::vector<FieldT> rand_items = {
        FieldT::random_element(), FieldT::random_element(),
        FieldT::random_element(), FieldT::random_element(),
        FieldT::random_element(), FieldT::random_element(),
        FieldT::random_element(), FieldT::random_element(),
        FieldT::random_element(), FieldT::random_element()
    };

    // Allocate items first
    pb_variable_array<FieldT> in_items;    
    in_items.allocate(pb, rand_items.size());
    in_items.fill_with_field_elements(pb, rand_items);

    // Our item comes afterwards, is a private input
    pb_variable<FieldT> in_our_item;
    in_our_item.allocate(pb);
    pb.val(in_our_item) = rand_items[3];

    // Setup gadget
    one_of_n<FieldT> the_gadget(pb, in_our_item, in_items);
    the_gadget.generate_r1cs_witness();
    the_gadget.generate_r1cs_constraints();
    pb.set_input_sizes(rand_items.size());

    if( ! pb.is_satisfied() ) {
        std::cerr << "Not satisfied!\n";
        return false;
    }

    auto constraints = pb.get_constraint_system();
    auto keypair = r1cs_ppzksnark_generator<ppT>(constraints);

    auto primary_input = pb.primary_input();
    auto auxiliary_input = pb.auxiliary_input();
    auto proof = r1cs_ppzksnark_prover<ppT>(keypair.pk, primary_input, auxiliary_input);

    return libsnark::r1cs_ppzksnark_verifier_strong_IC <ppT> (keypair.vk, primary_input, proof);
}


int main( int argc, char **argv )
{
    // Types for board
    typedef libff::alt_bn128_pp ppT;    
    ppT::init_public_params();

    if( ! test_one_of_n<ppT>() )
    {
        std::cerr << "FAIL\n";
        return 1;
    }

    std::cout << "OK\n";
    return 0;
}
