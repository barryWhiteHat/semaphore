#include "export.hpp"
#include "import.cpp"
#include "utils.hpp"

typedef libff::alt_bn128_pp ppT;

using std::cout;
using std::cerr;

int main( int argc, char **argv )
{
	ppT::init_public_params();

	if( argc < 3 ) {
		fprintf(stderr, "Usage: %s <vk.raw> <vk.json>\n", argv[0]);
		return 1;
	}

	// Load raw serialised VK
	auto vk = loadFromFile<r1cs_gg_ppzksnark_zok_verification_key<ppT>> (argv[1]);

	// Dump JSON serialised VK
	vk2json_file<ppT>(vk, argv[2]);

	// Load JSON serialised VK
	std::ifstream vk_input(argv[2]);
	std::stringstream vk_stream;
	vk_stream << vk_input.rdbuf();
	auto vk_json = vk_from_json<ppT>(vk_stream);

	// Verify serialisation is correct
	if( ! (vk_json == vk) ) {
		cerr << "FAIL\n";
		return 1;
	}

	cout << "OK";
	return 0;
}