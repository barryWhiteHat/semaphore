#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>

#include <stdio.h>
#include <stdlib.h>

#include <openssl/sha.h>
#include <openssl/rand.h>

#include "mod_hashpreimage.cpp"
#include "sha256/utils.cpp"
#include "ZoKrates/wraplibsnark.cpp"
#include "export.cpp"


int main( int argc, char **argv )
{
    uint8_t input_buffer[SHA256_block_size_bytes];
    const char *out_filename = NULL;    

    if( argc < 3 ) {
        std::cerr << "Usage: " << argv[0] << " <pk.raw> <0x...64_bytes_as_hex> [proof.json]\n";
        std::cerr << "Without [proof.json] it will be echo'd to stdout\n";
        return 1;
    }

    if( argc >= 3 ) {
        out_filename = argv[3];
    }

    if( ! hex_to_bytes(argv[2], input_buffer, SHA256_block_size_bytes) )
    {
        std::cerr << "Error: couldn't parse `input_buffer` from: " << argv[1] << "\n";
        return 2;
    }

    // ----------------------------------------------------------------
    // Types for board

    typedef libff::alt_bn128_pp ppT;
    typedef libff::Fr<ppT> FieldT;
    ppT::init_public_params();

    auto proving_key = loadFromFile<r1cs_ppzksnark_proving_key<ppT>> (argv[1]);

    // ----------------------------------------------------------------
    // Setup circuit to prove SHA256(private<input_buffer>) == public<output>

    protoboard<FieldT> pb;

    mod_hashpreimage<FieldT> mod(pb, "mod_hashpreimage");

    mod.generate_r1cs_constraints();

    mod.generate_r1cs_witness(input_buffer);

    if( ! pb.is_satisfied() )
    {
        std::cerr << "FAIL\n";
        return 4;
    }

    // ----------------------------------------------------------------
    // Prove the circuit

    auto primary_input = pb.primary_input();
    auto proof = r1cs_ppzksnark_prover<ppT>(proving_key, primary_input, pb.auxiliary_input());

    // ----------------------------------------------------------------
    // Then output the proof as JSON
    auto json = proof_to_json(proof, primary_input);

    if( ! out_filename )
    {
        std::cout << json << "\n";
    }
    else {
        std::ofstream fh;
        fh.open(out_filename, std::ios::binary);
        fh << json;
        fh.flush();
        fh.close();
    }

    return 0;
}
