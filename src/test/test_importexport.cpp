#include "import.cpp"
#include "export.cpp"

#include <sstream>


static const char static_proof[] = "{\n"
" \"a\" :[\"0x2a11cd2f23f4e729cd410542a6e805d70ca69b1686d24b1d6ef8b612963c70e5\", \"0x14444ba6ae0bd2bc58918362929f5e51073f88169ba0c7b7fedf21ceec73bf51\"],\n"
" \"a_p\"  :[\"0x6ee678bfcf1a7e518654b30a77f9c515e8730ae0da1c89681e8a104677b8112\", \"0xd83ed7f696a905ebb9a7d34f997077cb952e105dff01725ad417a8c2fbcfe17\"],\n"
" \"b\"  :[[\"0x122e0bd69dd1c3636f552173a55b848133cdf67797b08f13afa73b21176c2f59\", \"0x1248fd9578bf789755a826328ccbf4c186fc2c65ca2fe2c33c14c3ae43db2efe\"],\n"
" [\"0x3cd5718ce9d581e9ed698276caa41dcaa6f214d00f264d235051f85e8ea9134\", \"0x60f033ca5a53af623381f8e872baa64aa596280c26e752978ae947b98c620a6\"]],\n"
" \"b_p\" :[\"0x21d9e704d6af36eafda233868cebfbda28074109de1a7a0993113e918434cc48\", \"0x290769673bde80c992da6b4d2e5b1afb43723662375d218046ccac68cb474cd6\"],\n"
" \"c\" :[\"0x1943ec84fab09e6b87bcaeecad0958b057a56922c3bd25313d8d2c1e6d6ea96d\", \"0x25703ad43332da125dea38f6a799a31b76be8e61fbf17b4d93d9d3e358515732\"],\n"
" \"c_p\" :[\"0x2fda61d4050d9dbb7f364a42ad676db7369d41223d27f46aaed34626a7ce99f6\", \"0x1e4b623b6e0c3e54010d0c6b922b82f997f883b666a0e9d07965b23e7a600172\"],\n"
" \"h\" :[\"0xc4e8157201668d43f41a0c7ad1bdf780be49befd47b9709c62f64515aec76ff\", \"0x284dcd45754b3ecb0f4b0c05958191206d93726f04191fecf524245b2dda1dcf\"],\n"
" \"k\" :[\"0x1bdb8cb01b6e1ed8337ce75262e81ddcae4af1a5e4360f8838b75990c1e00c79\", \"0x2e02bd31dc64fc33f1cd44b3e7534b57f2fb7c1709816fdf91ab1d027dd25415\"],\n"
" \"input\" :[\"0x6f63883e503af3bf844c55046e43b5c79f7676c67327d0267f2e1a1a76f294b\", \"0x7\"]\n"
"}";


int main( int argc, char **argv )
{
	typedef libff::alt_bn128_pp ppT;
	typedef libff::Fr<ppT> FieldT;
	ppT::init_public_params();

	std::stringstream proof_input;
	proof_input << static_proof;

	auto proof = proof_from_json<ppT>(proof_input);

	auto proof_output = proof_to_json<ppT>(proof.second, proof.first);

	const char *proof_output_cstr = proof_output.c_str();

	if( 0 != strcmp(static_proof, proof_output_cstr) )
	{
		std::cerr << "FAIL: proof doesn't match!\n";
		std::cerr << proof_output << "\n";

		size_t po_len = strlen(proof_output_cstr);
		size_t sp_len = strlen(static_proof);
		if( po_len != sp_len ) {
			std::cerr << "Length mismatch! " << po_len << " " << sp_len << "\n";
			return 1;
		}

		return 2;
	}

	return 0;
}
