// Copyright (c) 2018 HarryR
// License: LGPL-3.0+

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

#include "r1cs_gg_ppzksnark_zok/r1cs_gg_ppzksnark_zok.hpp"

#include "gadgets/longsightf.cpp"


using libsnark::r1cs_gg_ppzksnark_zok_generator;
using libsnark::r1cs_gg_ppzksnark_zok_prover;
using libsnark::r1cs_gg_ppzksnark_zok_verifier_strong_IC;


template<typename ppT>
bool test_LongsightF()
{
    typedef libff::Fr<ppT> FieldT;

    std::vector<FieldT> round_constants;
    LongsightF322p5_constants_fill(round_constants);

    protoboard<FieldT> pb;

    auto rand_L = FieldT("3703141493535563179657531719960160174296085208671919316200479060314459804651"); // FieldT::random_element();
    auto rand_R = FieldT("134551314051432487569247388144051420116740427803855572138106146683954151557"); // FieldT::random_element();

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

    auto result_expected = FieldT("1955118202659622298192442035507501123132991419752400995882287708761535290053");
    if( result_expected != pb.val(the_gadget.result()) ) {
        std::cerr << "Unexpected result!\n";
        return false;
    }


    if( ! pb.is_satisfied() ) {
        std::cerr << "Not satisfied!\n";
        return false;
    }

    std::cout << pb.num_constraints() << " constraints" << std::endl;

    auto constraints = pb.get_constraint_system();

    auto keypair = r1cs_gg_ppzksnark_zok_generator<ppT>(constraints);

    auto primary_input = pb.primary_input();
    auto auxiliary_input = pb.auxiliary_input();
    auto proof = r1cs_gg_ppzksnark_zok_prover<ppT>(keypair.pk, primary_input, auxiliary_input);
    return r1cs_gg_ppzksnark_zok_verifier_strong_IC <ppT> (keypair.vk, primary_input, proof);
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
