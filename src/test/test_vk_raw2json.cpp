#include "export.hpp"
#include "import.hpp"
#include "utils.hpp"

using std::cout;
using std::cerr;
using ethsnarks::vk2json_file;
using ethsnarks::ppT;
using ethsnarks::VerificationKeyT;
using ethsnarks::vk_from_json;
using ethsnarks::loadFromFile;

int main( int argc, char **argv )
{
	ppT::init_public_params();

	if( argc < 3 ) {
		fprintf(stderr, "Usage: %s <vk.raw> <vk.json>\n", argv[0]);
		return 1;
	}

	// Load raw serialised VK
	auto vk = loadFromFile<VerificationKeyT> (argv[1]);

	// Dump JSON serialised VK
	vk2json_file(vk, argv[2]);

	// Load JSON serialised VK
	std::ifstream vk_input(argv[2]);
	std::stringstream vk_stream;
	vk_stream << vk_input.rdbuf();
	auto vk_json = vk_from_json(vk_stream);

	// Verify serialisation is correct
	if( ! (vk_json == vk) ) {
		cerr << "FAIL\n";
		return 1;
	}

	cout << "OK";
	return 0;
}