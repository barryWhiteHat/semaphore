#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>

#include <stdio.h>
#include <stdlib.h>

#include <openssl/sha.h>
#include <openssl/rand.h>

#include "mod_hashpreimage.cpp"
#include "sha256/utils.cpp"


static const size_t SHA256_digest_size_bytes = SHA256_digest_size / 8;
static const size_t SHA256_block_size_bytes = SHA256_block_size / 8;


int main( int argc, char **argv )
{
	if( argc < 3 ) {
		fprintf(stderr, "Usage: %s <pk-output.raw> <vk-output.json>\n", argv[0]);
		return 1;
	}

	// Types for board
	typedef libff::alt_bn128_pp ppT;
	typedef libff::Fr<ppT> FieldT;
	ppT::init_public_params();

	// ----------------------------------------------------------------

    uint8_t input_buffer[SHA256_block_size_bytes];
    uint8_t output_digest[SHA256_digest_size_bytes];

    RAND_bytes(input_buffer, sizeof(input_buffer));

	SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, input_buffer, sizeof(input_buffer));    
    SHA256_Final(output_digest, &ctx);

    // ----------------------------------------------------------------

    const auto input_bv = bytes_to_bv(input_buffer, SHA256_block_size_bytes);
    const auto output_bv = bytes_to_bv(output_digest, SHA256_digest_size_bytes);

    // ----------------------------------------------------------------

	protoboard<FieldT> pb;

	mod_hashpreimage<FieldT> mod(pb, "mod_hashpreimage");

	mod.generate_r1cs_constraints();

	mod.generate_r1cs_witness(input_bv, output_bv);

	std::cout << "Constraints: " << pb.num_constraints() << "\n";
    std::cout << "Variables: " << pb.num_variables() << "\n";
    std::cout << "Inputs: " << pb.num_inputs() << "\n";

    for( auto& pb_inp : pb.primary_input() )
    {
    	std::cout << pb_inp << "\n";
    }

	auto input_buffer_bits = bytes_to_bv(input_buffer, sizeof(input_buffer));
	auto block_bits = mod.input_block.get_block();
	print_bv("input (bytes)", input_buffer_bits);
	print_bv("input  (r1cs)", block_bits);

	auto output_digest_bits = bytes_to_bv(output_digest, sizeof(output_digest));
	auto output_bits = mod.output.get_digest();
	print_bv("output (bytes)", output_digest_bits);
	print_bv("output  (r1cs)", output_bits);

	if( pb.is_satisfied() )
	{
		std::cout << "OK\n";
		return 0;
	}

	std::cerr << "FAIL\n";
	return 1;
}
