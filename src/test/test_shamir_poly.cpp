#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

#include "gadgets/shamir_poly.cpp"


template<typename FieldT>
bool test_shamirs_poly()
{
    protoboard<FieldT> pb;

    auto rand_input = FieldT::random_element();
    std::vector<FieldT> rand_alpha = {
        FieldT::random_element(), FieldT::random_element(),
        FieldT::random_element(), FieldT::random_element()
    };

    pb_variable<FieldT> in_input;
    pb_variable_array<FieldT> in_alpha;
    pb_variable<FieldT> output;

    in_input.allocate(pb);
    pb.val(in_input) = rand_input;

    in_alpha.allocate(pb, rand_alpha.size());
    in_alpha.fill_with_field_elements(pb, rand_alpha);

    shamir_poly<FieldT> the_gadget(pb, in_input, in_alpha, output);

    the_gadget.generate_r1cs_witness();

    the_gadget.generate_r1cs_constraints();

    std::cout << "I " << rand_input << std::endl;
    for( size_t i = 0; i < in_alpha.size(); i++ ) {
        std::cout << "A[" << i << "] " << rand_alpha[i] << std::endl;
        std::cout << "S[" << i << "] " << pb.val(the_gadget.intermediate_squares[i]) << std::endl;
        std::cout << "T[" << i << "] " << pb.val(the_gadget.intermediate_total[i]) << std::endl;
        std::cout << std::endl;
    }

    return pb.is_satisfied();
}


int main( int argc, char **argv )
{
    // Types for board
    typedef libff::alt_bn128_pp ppT;
    typedef libff::Fr<ppT> FieldT;
    ppT::init_public_params();

    if( ! test_shamirs_poly<FieldT>() )
    {
        std::cerr << "FAIL\n";
        return 1;
    }

    std::cout << "OK\n";
    return 0;
}
