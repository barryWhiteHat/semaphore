#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>

#include <stdio.h>
#include <stdlib.h>

#include <openssl/sha.h>
#include <openssl/rand.h>

#include "mod_hashpreimage.cpp"
#include "export.cpp"


int main( int argc, char **argv )
{
    if( argc < 3 ) {
        fprintf(stderr, "Usage: %s <pk-output.raw> <vk-output.json>\n", argv[0]);
        return 1;
    }

    // Types for board
    typedef libff::alt_bn128_pp ppT;
    typedef libff::Fr<ppT> FieldT;
    ppT::init_public_params();

    protoboard<FieldT> pb;
    mod_hashpreimage<FieldT> mod(pb, "mod_hashpreimage");
    mod.generate_r1cs_constraints();

    auto keypair = r1cs_ppzksnark_generator<ppT>(pb.get_constraint_system());
    vk2json<ppT>(keypair.vk, argv[2]);
    writeToFile(argv[1], keypair.pk);

    return 0;
}
