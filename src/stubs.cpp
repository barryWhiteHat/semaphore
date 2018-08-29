#include <libsnark/gadgetlib1/protoboard.hpp>

#include <sstream>  // stringstream

#include "ethsnarks.hpp"
#include "utils.hpp"
#include "import.cpp"
#include "export.hpp"

namespace ethsnarks {

bool stub_verify( const char *vk_json, const char *proof_json )
{
    ppT::init_public_params();

    std::stringstream vk_stream;
    vk_stream << vk_json;
    auto vk = vk_from_json<ppT>(vk_stream);

    std::stringstream proof_stream;
    proof_stream << proof_json;
    auto proof_pair = proof_from_json<ppT>(proof_stream);

    auto status = libsnark::r1cs_gg_ppzksnark_zok_verifier_strong_IC <ppT> (vk, proof_pair.first, proof_pair.second);
    if( status )
        return true;

    return false;
}


int stub_main_verify( const char *prog_name, int argc, char **argv )
{
    if( argc < 3 )
    {
        std::cerr << "Usage: " << prog_name << " " << argv[0] << " <vk.json> <proof.json>" << std::endl;
        return 1;
    }

    auto vk_json_file = argv[1];
    auto proof_json_file = argv[2];

    // Read verifying key file
    std::stringstream vk_stream;
    std::ifstream vk_input(vk_json_file);
    if( ! vk_input ) {
        std::cerr << "Error: cannot open " << vk_json_file << std::endl;
        return 2;
    }
    vk_stream << vk_input.rdbuf();
    vk_input.close();

    // Read proof file
    std::stringstream proof_stream;
    std::ifstream proof_input(proof_json_file);
    if( ! proof_input ) {
        std::cerr << "Error: cannot open " << proof_json_file << std::endl;
        return 2;
    }
    proof_stream << proof_input.rdbuf();
    proof_input.close();

    // Then verify if proof is correct
    auto vk_str = vk_stream.str();
    auto proof_str = proof_stream.str();
    if( stub_verify( vk_str.c_str(), proof_str.c_str() ) )
    {
        return 0;
    }

    std::cerr << "Error: failed to verify proof!" << std::endl;

    return 1;
}

}
// namespace ethsnarks
