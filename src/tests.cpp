#include <cassert>

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

typedef libff::alt_bn128_pp ppT;
typedef typename ppT::Fq_type Fq_T;

int main( int argc, char **argv )
{
	libff::alt_bn128_pp::init_public_params();

	// Verify that hex encoding of field elements decodes correctly
	Fq_T x("21888242871839275222246405745257275088548364400416034343698204186575808495617");
	Fq_T y("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001");

	std::cout << "X " << x << "\n";
	std::cout << "Y " << y << "\n";
	std::cout << "r " << libff::alt_bn128_modulus_r << "\n";

	if( y == libff::alt_bn128_modulus_r 
	 && x == libff::alt_bn128_modulus_r
	 && x == y )
	{
		printf("OK\n");
	}
	
	return 0;
}