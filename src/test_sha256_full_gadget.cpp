#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

#include "sha256/sha256_full_gadget.cpp"
#include "sha256/utils.cpp"


#include <openssl/sha.h>
#include <openssl/rand.h>


static const size_t SHA256_digest_size_bytes = SHA256_digest_size / 8;
static const size_t SHA256_block_size_bytes = SHA256_block_size / 8;


/**
* Verifies that the SHA256_full gadget matches a reference implementation
*
* Runs SHA256_Update with a full block
* Verifies that the state matches
*
* TODO:
*  - Flip bits in Witness
*  - Flip bits in left/right
*  - all flip options toggleable
*/
template<typename FieldT>
bool test_sha256_full_gadget()
{
    // Create a block_size'd buffer of random bytes
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    uint8_t input_buffer[SHA256_block_size_bytes];
    uint8_t output_digest[SHA256_digest_size_bytes];
    assert( SHA256_block_size / 2 == SHA256_digest_size );
    RAND_bytes(input_buffer, sizeof(input_buffer));

    // Then perform a full round of SHA256
    SHA256_Update(&ctx, input_buffer, sizeof(input_buffer));    
    SHA256_Final(output_digest, &ctx);

    // ----------------------------------------------------------------
    // Setup circuit to do full_output = SHA256(left, right)

    protoboard<FieldT> pb;

    // split the input buffer into the right & left components
    digest_variable<FieldT> left(pb, SHA256_digest_size, "left");
    digest_variable<FieldT> right(pb, SHA256_digest_size, "right");

    const libff::bit_vector left_bv = bytes_to_bv(input_buffer, SHA256_digest_size_bytes);
    const libff::bit_vector right_bv = bytes_to_bv(&input_buffer[SHA256_digest_size_bytes], SHA256_digest_size_bytes);

    left.generate_r1cs_witness(left_bv);
    right.generate_r1cs_witness(right_bv);

    // Then run a full SHA256 round, via R1CS SNARK circuit
    block_variable<FieldT> full_input(pb, left, right, "full_input");
    digest_variable<FieldT> full_output(pb, SHA256_digest_size, "full_output");
    sha256_full_gadget_512<FieldT> full_gadget(pb, full_input, full_output, "full_gadget");

    full_gadget.generate_r1cs_constraints();
    full_gadget.generate_r1cs_witness();

    // ----------------------------------------------------------------    

    // Binds circuit satisfiability to whether or not the full output
    // matches what was computed by OpenSSL's SHA256
    auto output_digest_bits = bytes_to_bv(output_digest, SHA256_digest_size_bytes);
	full_output.generate_r1cs_witness(output_digest_bits);

	// Show the two side-by-side
	auto full_output_bits = full_output.get_digest();
    print_bv("full (r1cs)", full_output_bits);
    print_bv("full (SHA2)", output_digest_bits);

    std::cout << "Constraints: " << pb.num_constraints() << "\n";
    std::cout << "Variables: " << pb.num_variables() << "\n";
    std::cout << "Inputs: " << pb.num_inputs() << "\n";

    return pb.is_satisfied();
}

int main( int argc, char **argv )
{
	// Types for board
	typedef libff::alt_bn128_pp ppT;
	typedef libff::Fr<ppT> FieldT;
	ppT::init_public_params();

	if( ! test_sha256_full_gadget<FieldT>() )
	{
		std::cerr << "FAIL\n";
		return 1;
	}

	std::cout << "OK\n";
	return 0;
}
