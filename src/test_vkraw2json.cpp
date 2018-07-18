#include "export.cpp"
#include "ZoKrates/wraplibsnark.hpp"

typedef libff::alt_bn128_pp ppT;

int main( int argc, char **argv )
{
	libff::alt_bn128_pp::init_public_params();

	if( argc < 3 ) {
		fprintf(stderr, "Usage: %s <vk.raw> <vk.json>\n", argv[0]);
		return 1;
	}

	auto vk = loadFromFile<r1cs_ppzksnark_verification_key<ppT>> (argv[1]);
	writeToFile("test.raw", vk);
	vk2json<ppT>(vk, argv[2]);

	return 0;
}