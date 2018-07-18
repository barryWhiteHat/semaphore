#include <cstdio>
#include <cstring>
#include <istream>
#include <fstream>

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

#include "import.cpp"

using namespace std;

typedef libff::alt_bn128_pp ppT;

struct noop {
	void operator()(...) const {}
};

int main( int argc, char **argv )
{
	if( argc < 2 )
	{
		::fprintf(stderr, "Usage: %s <vk.json> [proof.json]\n", argv[0]);
		return 1;
	}

	// Read input file (or stdin) into vk_stream;
	ostringstream vk_stream;
	if( 0 == ::strcmp(argv[1], "-") ) {
		vk_stream << cin.rdbuf();
	}
	else {
		ifstream vk_input(argv[1]);
		if( ! vk_input ) {
			::fprintf(stderr, "Error: cannot open %s\n", argv[1]);
			return 2;
		}
		vk_stream << vk_input.rdbuf();
		vk_input.close();
	}

	auto vk = vk_from_json<ppT>(vk_stream.str());

	return 0;
}