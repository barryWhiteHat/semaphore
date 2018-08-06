#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>

#include "gadgets/shamir_poly.cpp"


using libsnark::r1cs_ppzksnark_generator;
using libsnark::r1cs_ppzksnark_prover;


template<typename ppT>
bool test_shamirs_poly()
{
    typedef libff::Fr<ppT> FieldT;

    protoboard<FieldT> pb;

    auto rand_input = FieldT::random_element();
    std::vector<FieldT> rand_alpha = {
        FieldT::random_element(), FieldT::random_element(),
        FieldT::random_element(), FieldT::random_element()
    };

    pb_variable<FieldT> in_input;
    pb_variable_array<FieldT> in_alpha;

    in_input.allocate(pb);
    pb.val(in_input) = rand_input;

    in_alpha.allocate(pb, rand_alpha.size());
    in_alpha.fill_with_field_elements(pb, rand_alpha);

    shamir_poly<FieldT> the_gadget(pb, in_input, in_alpha);

    the_gadget.generate_r1cs_witness();

    the_gadget.generate_r1cs_constraints();

    pb.set_input_sizes(1);

    std::cout << "I " << rand_input << std::endl;
    for( size_t i = 0; i < in_alpha.size(); i++ ) {
        std::cout << "A[" << i << "] " << rand_alpha[i] << std::endl;
        std::cout << "S[" << i << "] " << pb.val(the_gadget.intermediate_squares[i]) << std::endl;
        std::cout << "T[" << i << "] " << pb.val(the_gadget.intermediate_total[i]) << std::endl;
        std::cout << std::endl;
    }

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

    if( ! test_shamirs_poly<ppT>() )
    {
        std::cerr << "FAIL\n";
        return 1;
    }

    std::cout << "OK\n";
    return 0;
}
