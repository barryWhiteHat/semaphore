// Copyright (c) 2018 HarryR
// License: LGPL-3.0+


#include "r1cs_gg_ppzksnark_zok/r1cs_gg_ppzksnark_zok.hpp"

#include "gadgets/longsightl.hpp"

using libsnark::protoboard;
using libsnark::pb_variable;
using libsnark::r1cs_gg_ppzksnark_zok_generator;
using libsnark::r1cs_gg_ppzksnark_zok_prover;
using libsnark::r1cs_gg_ppzksnark_zok_verifier_strong_IC;

using ethsnarks::ppT;
using ethsnarks::FieldT;

bool test_LongsightL()
{
    std::vector<FieldT> round_constants;
    LongsightL12p5_constants_fill(round_constants);

    protoboard<FieldT> pb;

    pb_variable<FieldT> in_x;
    pb_variable<FieldT> in_k;

    in_x.allocate(pb);
    pb.val(in_x) = FieldT("3703141493535563179657531719960160174296085208671919316200479060314459804651");

    in_k.allocate(pb);
    pb.val(in_k) = FieldT("134551314051432487569247388144051420116740427803855572138106146683954151557");

    LongsightL_gadget the_gadget(pb, round_constants, in_x, in_k);
    the_gadget.generate_r1cs_witness();
    the_gadget.generate_r1cs_constraints();

    pb.set_input_sizes(2);

    auto result_expected = FieldT("9638538253242078011815100086590507856430665299520185056351852605094082194804");
    if( result_expected != pb.val(the_gadget.result()) ) {
        std::cerr << "Unexpected result!\n";
        std::cerr << "Got " << pb.val(the_gadget.result()) << "\n";
        return false;
    }

    std::cout << pb.num_constraints() << " constraints" << std::endl;

    return pb.is_satisfied();
}


int main( int argc, char **argv )
{
    // Types for board
    ppT::init_public_params();

    if( ! test_LongsightL() )
    {
        std::cerr << "FAIL\n";
        return 1;
    }

    std::cout << "OK\n";
    return 0;
}
