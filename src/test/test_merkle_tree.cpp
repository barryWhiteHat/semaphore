#include "stubs.hpp"
#include "gadgets/merkle_tree.cpp"

namespace ethsnarks {


bool test_merkle_path_selector(int is_right)
{
	ProtoboardT pb;

	const auto value_A = FieldT("149674538925118052205057075966660054952481571156186698930522557832224430770");
	const auto value_B = FieldT("9670701465464311903249220692483401938888498641874948577387207195814981706974");

	is_right = is_right ? 1 : 0;

	VariableT var_A = make_variable(pb);
	pb.val(var_A) = value_A;

	VariableT var_B = make_variable(pb);
	pb.val(var_B) = value_B;

	VariableT var_is_right = make_variable(pb);
	pb.val(var_is_right) = is_right;

	merkle_path_selector selector(pb, var_A, var_B, var_is_right);

	selector.generate_r1cs_witness();
	selector.generate_r1cs_constraints();

	if( is_right ) {
		if( pb.val(selector.left()) != value_B ) {
			return false;
		}
		if( pb.val(selector.right()) != value_A ) {
			return false;
		}
	}
	else {
		if( pb.val(selector.left()) != value_A ) {
			return false;
		}
		if( pb.val(selector.right()) != value_B ) {
			return false;
		}
	}

	if( ! pb.is_satisfied() ) {
		std::cerr << "FAIL merkle_path_authenticator is_satisfied\n";
		return false;
	}

	return stub_test_proof_verify(pb);
}


bool test_merkle_path_authenticator() {
	ProtoboardT pb;

	VariableArrayT address_bits;

	size_t tree_depth = 1;
	return true;
}

// namespace ethsnarks
}


int main( int argc, char **argv )
{
    ethsnarks::ppT::init_public_params();

    if( ! ethsnarks::test_merkle_path_authenticator() )
    {
        std::cerr << "FAIL merkle_path_authenticator\n";
        return 1;
    }

    if( ! ethsnarks::test_merkle_path_selector(0) )
    {
        std::cerr << "FAIL merkle_path_selector 0\n";
        return 2;
    }

    if( ! ethsnarks::test_merkle_path_selector(1) )
    {
        std::cerr << "FAIL merkle_path_selector 1\n";
        return 2;
    }

    std::cout << "OK\n";
    return 0;
}

