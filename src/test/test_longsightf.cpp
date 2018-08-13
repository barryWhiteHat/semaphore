// Copyright (c) 2018 HarryR
// License: LGPL-3.0+

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>

#include "gadgets/longsightf.cpp"


using libsnark::r1cs_ppzksnark_generator;
using libsnark::r1cs_ppzksnark_prover;


template<typename ppT>
bool test_LongsightF()
{
    typedef libff::Fr<ppT> FieldT;

    std::vector<FieldT> round_constants;
    LongsightF152p5_constants(round_constants);

    protoboard<FieldT> pb;

    auto rand_L = FieldT("21871881226116355513319084168586976250335411806112527735069209751513595455673"); // FieldT::random_element();
    auto rand_R = FieldT("55049861378429053168722197095693172831329974911537953231866155060049976290"); // FieldT::random_element();

    pb_variable<FieldT> in_xL;
    pb_variable<FieldT> in_xR;

    in_xL.allocate(pb);
    pb.val(in_xL) = rand_L;

    in_xR.allocate(pb);
    pb.val(in_xR) = rand_R;

    LongsightF_gadget<FieldT> the_gadget(pb, round_constants, in_xL, in_xR);

    the_gadget.generate_r1cs_witness();

    the_gadget.generate_r1cs_constraints();

    pb.set_input_sizes(2);

    std::cout << "Result: " << pb.val(the_gadget.result()) <<  "\n";

    if( ! pb.is_satisfied() ) {
        std::cerr << "Not satisfied!\n";
        return false;
    }

    auto constraints = pb.get_constraint_system();

    std::cout << "Setup keypair\n";
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

    if( ! test_LongsightF<ppT>() )
    {
        std::cerr << "FAIL\n";
        return 1;
    }

    std::cout << "OK\n";
    return 0;
}
