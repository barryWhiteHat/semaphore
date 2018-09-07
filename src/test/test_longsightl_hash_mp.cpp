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

    pb_variable<FieldT> m_0;
    pb_variable<FieldT> m_1;
    pb_variable<FieldT> iv;

    m_0.allocate(pb);
    pb.val(m_0) = FieldT("3703141493535563179657531719960160174296085208671919316200479060314459804651");

    m_1.allocate(pb);
    pb.val(m_1) = FieldT("134551314051432487569247388144051420116740427803855572138106146683954151557");

    iv.allocate(pb);
    pb.val(iv) = FieldT("918403109389145570117360101535982733651217667914747213867238065296420114726");

    LongsightL12p5_MP_gadget the_gadget(pb, iv, {m_0, m_1});
    the_gadget.generate_r1cs_witness();
    the_gadget.generate_r1cs_constraints();

    pb.set_input_sizes(1);

    auto result_expected = FieldT("16743249391414211194903251836323254089433285237756741022465555151301952011503");
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
