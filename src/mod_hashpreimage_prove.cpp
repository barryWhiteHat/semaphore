#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>

#include <stdio.h>
#include <stdlib.h>

#include <openssl/sha.h>
#include <openssl/rand.h>

#include "mod_hashpreimage.cpp"
#include "sha256/utils.cpp"


int main( int argc, char **argv )
{
    if( argc < 4 ) {
        fprintf(stderr, "Usage: %s <0xleft> <0xright> [proof.json]\n", argv[0]);
        return 1;
    }

    // Types for board
    typedef libff::alt_bn128_pp ppT;
    typedef libff::Fr<ppT> FieldT;
    ppT::init_public_params();

    // ----------------------------------------------------------------

    uint8_t input_buffer[SHA256_block_size_bytes];
    uint8_t output_digest[SHA256_digest_size_bytes];

    SHA256_CTX ctx;

    // 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a089f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08'
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, "test", 4);
    SHA256_Final(input_buffer, &ctx);
    memcpy(&input_buffer[SHA256_digest_size_bytes], input_buffer, SHA256_digest_size_bytes);

    SHA256_Init(&ctx);
    SHA256_Update(&ctx, input_buffer, sizeof(input_buffer));    
    SHA256_Final(output_digest, &ctx);

    uint8_t output_expected[] = {0xD2, 0x94, 0xF6, 0xE5, 0x85, 0x87, 0x4F, 0xE6, 0x40, 0xBE, 0x4C, 0xE6, 0x36, 0xE6, 0xEF, 0x9E, 0x3A, 0xDC, 0x27, 0x62, 0x0A, 0xA3, 0x22, 0x1F, 0xDC, 0xF5, 0xC0, 0xA7, 0xC1, 0x1C, 0x6F, 0x67};
    if( memcmp(output_digest, output_expected, sizeof(output_digest)) != 0 ) {
        printf("output_digest mismatch!\n");
        return 1;
    }

    // ----------------------------------------------------------------

    protoboard<FieldT> pb;

    mod_hashpreimage<FieldT> mod(pb, "mod_hashpreimage");

    mod.generate_r1cs_constraints();

    mod.generate_r1cs_witness(input_buffer);

    auto input_buffer_bits = bytes_to_bv(input_buffer, sizeof(input_buffer));
    auto block_bits = mod.input_block.get_block();
    print_bv("input (bytes)", input_buffer_bits);
    print_bv("input  (r1cs)", block_bits);

    auto output_digest_bits = bytes_to_bv(output_digest, sizeof(output_digest));
    auto output_bits = mod.output.get_digest();
    print_bv("output (bytes)", output_digest_bits);
    print_bv("output  (r1cs)", output_bits);

    for( auto& var : pb.primary_input() )
    {
        std::cout << "var " << var << "\n";
    }

    std::cout << "Constraints: " << pb.num_constraints() << "\n";

    if( pb.is_satisfied() )
    {
        std::cout << "OK\n";
        return 0;
    }

    std::cerr << "FAIL\n";
    return 1;
}
