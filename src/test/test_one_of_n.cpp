// Copyright (c) 2018 HarryR
// License: LGPL-3.0+

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

#include "r1cs_gg_ppzksnark_zok/r1cs_gg_ppzksnark_zok.hpp"

#include "gadgets/one_of_n.cpp"

#include "export.cpp"
#include "import.cpp"


using libsnark::r1cs_gg_ppzksnark_zok_generator;
using libsnark::r1cs_gg_ppzksnark_zok_prover;
using libsnark::r1cs_gg_ppzksnark_zok_verifier_strong_IC;


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
    auto keypair = r1cs_gg_ppzksnark_zok_generator<ppT>(constraints);

    auto primary_input = pb.primary_input();
    auto auxiliary_input = pb.auxiliary_input();
    auto proof = r1cs_gg_ppzksnark_zok_prover<ppT>(keypair.pk, primary_input, auxiliary_input);

    auto proof_ok = r1cs_gg_ppzksnark_zok_verifier_strong_IC <ppT> (keypair.vk, primary_input, proof);
    if( ! proof_ok ) {
        std::cerr << "Verifier failed!\n";
        return false;
    }

    // Verify that serialising and unserialising the proof and input via json
    // results in the same proof and input
    stringstream proof_json_stream;
    proof_json_stream << proof_to_json<ppT>(proof, primary_input);
    auto loaded_proof = proof_from_json<ppT>(proof_json_stream);
    if( loaded_proof.first != primary_input ) {
        std::cerr << "Loaded primary input mismatch!\n";
        return false;
    }
    if( false == (loaded_proof.second == proof) ) {
        std::cerr << "Loaded proof mismatch!\n";
        return false;
    }

    // Then check if verification key can be serialised and unserialized
    stringstream saved_vk;
    saved_vk << vk2json<ppT>(keypair.vk);
    auto loaded_vk = vk_from_json<ppT>(saved_vk);
    if( false == (loaded_vk == keypair.vk) ) {
        std::cerr << "VK serialise/unserialise error!\n";
        return false;
    }

    return true;
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
