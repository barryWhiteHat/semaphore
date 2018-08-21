#pragma once

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

#include <sstream>  // stringstream
using std::stringstream;

bool stub_verify( const char *vk_json, const char *proof_json )
{
    typedef libff::alt_bn128_pp ppT;
    ppT::init_public_params();

    stringstream vk_stream;
    vk_stream << vk_json;
    auto vk = vk_from_json<ppT>(vk_stream);

    stringstream proof_stream;
    proof_stream << proof_json;
    auto proof_pair = proof_from_json<ppT>(proof_stream);

    auto status = libsnark::r1cs_gg_ppzksnark_zok_verifier_strong_IC <ppT> (vk, proof_pair.first, proof_pair.second);
    if( status )
        return true;

    return false;
}


template< template <class> class GadgetT >
int stub_genkeys( const char *pk_file, const char *vk_file )
{
    typedef libff::alt_bn128_pp ppT;
    typedef libff::Fr<ppT> FieldT;
    ppT::init_public_params();

    protoboard<FieldT> pb;
    GadgetT<FieldT> mod(pb, "module");
    mod.generate_r1cs_constraints();

    auto keypair = r1cs_gg_ppzksnark_zok_generator<ppT>(pb.get_constraint_system());
    vk2json_file<ppT>(keypair.vk, vk_file);
    writeToFile(pk_file, keypair.pk);

    return 0;
}


int stub_main_verify( const char *prog_name, int argc, char **argv )
{
    if( argc < 3 )
    {
        cerr << "Usage: " << prog_name << " " << argv[0] << " <vk.json> <proof.json>" << endl;
        return 1;
    }

    auto vk_json_file = argv[1];
    auto proof_json_file = argv[2];

    // Read verifying key file
    stringstream vk_stream;
    ifstream vk_input(vk_json_file);
    if( ! vk_input ) {
        cerr << "Error: cannot open " << vk_json_file << "\n";
        return 2;
    }
    vk_stream << vk_input.rdbuf();
    vk_input.close();

    // Read proof file
    stringstream proof_stream;
    ifstream proof_input(proof_json_file);
    if( ! proof_input ) {
        cerr << "Error: cannot open " << proof_json_file << "\n";
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

    cerr << "Error: failed to verify proof!\n";

    return 1;
}


template< template <class> class GadgetT >
static int stub_main_genkeys( const char *prog_name, int argc, char **argv )
{
    if( argc < 3 )
    {
        cerr << "Usage: " << prog_name << " " << argv[0] << " <pk-output.raw> <vk-output.json>\n";
        return 1;
    }

    auto pk_file = argv[1];
    auto vk_file = argv[2];

    if( 0 != stub_genkeys<GadgetT>( pk_file, vk_file ) )
    {
        cerr << "Error: failed to generate proving and verifying keys\n";
        return 1;
    }

    return 0;
}
