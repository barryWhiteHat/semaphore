#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>

#include <stdio.h>
#include <stdlib.h>

#include "mod_hashpreimage.cpp"


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

	printf("OK\n");
	return 0;
}
