/*    
    copyright 2018 to the Semaphore Authors

    This file is part of Semaphore.

    Semaphore is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Semaphore is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Semaphore.  If not, see <https://www.gnu.org/licenses/>.
*/


#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>

//hash

#include <sha256/sha256_ethereum.cpp>
#include <export.cpp>
#include "miximus.hpp"
//key gen 
#include "libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp" //hold key


#include <libsnark/common/data_structures/merkle_tree.hpp>
#include <libsnark/gadgetlib1/gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_authentication_path_variable.hpp>
#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_read_gadget.hpp>

#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_read_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_update_gadget.hpp>

using namespace libsnark;
using namespace libff;

typedef sha256_ethereum HashT;

template<typename FieldT, typename HashT>
class Miximus {
public:

    const size_t digest_len = HashT::get_digest_len();
    size_t tree_depth;
    protoboard<FieldT> pb;

    std::shared_ptr<multipacking_gadget<FieldT>> unpacker;

    //digest_variable<FieldT> root_digest(pb, digest_len, "root_digest");
    std::shared_ptr<digest_variable<FieldT>> root_digest;
    //digest_variable<FieldT> cm(pb, digest_len, "cm_digest");
    std::shared_ptr<digest_variable<FieldT>> cm;
    //digest_variable<FieldT> sk(pb, digest_len, "sk_digest");
    std::shared_ptr<digest_variable<FieldT>> sk;
    //digest_variable<FieldT> leaf_digest(pb, digest_len, "leaf_digest");
    std::shared_ptr<digest_variable<FieldT>> leaf_digest;

    std::shared_ptr<sha256_ethereum> cm_hash;
    std::shared_ptr<sha256_ethereum> nullifier_hash;

    // semaphore sprecifc variables
    std::shared_ptr<digest_variable<FieldT>> signal;
    std::shared_ptr<digest_variable<FieldT>> signal_variables;
    std::shared_ptr<digest_variable<FieldT>> external_nullifier;
    std::shared_ptr<digest_variable<FieldT>> nullifier;


    std::shared_ptr<merkle_authentication_path_variable<FieldT, HashT>> path_var;

    std::shared_ptr<merkle_tree_check_read_gadget<FieldT, HashT>> ml;

    pb_variable_array<FieldT> address_bits_va;
    std::shared_ptr <block_variable<FieldT>> input_variable;
    std::shared_ptr <block_variable<FieldT>> nullifier_variable;

    pb_variable<FieldT> ZERO;
    //we use layer 2 transaction abstration. 
    //here the depositor denotes the fee in Wei
    pb_variable<FieldT> msgSenderFee;

    pb_variable_array<FieldT> packed_inputs;
    pb_variable_array<FieldT> unpacked_inputs;

    Miximus(int _tree_depth) {
        tree_depth = _tree_depth;

        packed_inputs.allocate(pb, 5 + 1, "packed");

        msgSenderFee.allocate(pb, "msgSenderFee");
        ZERO.allocate(pb, "ZERO");
        pb.val(ZERO) = 0;
        address_bits_va.allocate(pb, tree_depth, "address_bits");

        cm.reset(new digest_variable<FieldT>(pb, 256, "cm"));
        root_digest.reset(new digest_variable<FieldT>(pb, 256, "root_digest"));
        sk.reset(new digest_variable<FieldT>(pb, 256, "sk"));
        leaf_digest.reset(new digest_variable<FieldT>(pb, 256, "leaf_digest"));

        signal.reset(new digest_variable<FieldT>(pb, 256, "signal"));
        signal_variables.reset(new digest_variable<FieldT>(pb, 256, "signal_variables"));
        external_nullifier.reset(new digest_variable<FieldT>(pb, 256, "external_nullifier"));
        nullifier.reset(new digest_variable<FieldT>(pb, 256, "nullifier"));


        //unpacked_inputs.insert(unpacked_inputs.end(), true );
        unpacked_inputs.insert(unpacked_inputs.end(), root_digest->bits.begin(), root_digest->bits.end());
        unpacked_inputs.insert(unpacked_inputs.end(), signal->bits.begin(), signal->bits.end());
        unpacked_inputs.insert(unpacked_inputs.end(), signal_variables->bits.begin(), signal_variables->bits.end());
        unpacked_inputs.insert(unpacked_inputs.end(), external_nullifier->bits.begin(), external_nullifier->bits.end());
        unpacked_inputs.insert(unpacked_inputs.end(), nullifier->bits.begin(), nullifier->bits.end());

        unpacker.reset(new multipacking_gadget<FieldT>(
            pb,
            unpacked_inputs,
            packed_inputs,
            FieldT::capacity(),
            "unpacker"
        ));

        pb.set_input_sizes(5 + 1 );

        input_variable.reset(new block_variable<FieldT>(pb, *cm, *sk, "input_variable")); 
        nullifier_variable.reset(new block_variable<FieldT>(pb, *cm, *external_nullifier, "nullifier_variable"));

        cm_hash.reset(new sha256_ethereum(
            pb, SHA256_block_size, *input_variable, *leaf_digest, "cm_hash"
        ));
        //sha256_ethereum g(pb, SHA256_block_size, *input_variable, *leaf_digest, "g");


        nullifier_hash.reset(new sha256_ethereum(
            pb, SHA256_block_size, *nullifier_variable, *nullifier, "nullifier_hash"
        ));


        path_var.reset(new merkle_authentication_path_variable<FieldT, HashT> (pb, tree_depth, "path_var" ));

        //merkle_authentication_path_variable<FieldT, HashT> path_var(pb, tree_depth, "path_var");

        ml.reset(new merkle_tree_check_read_gadget<FieldT, HashT>(pb, tree_depth, address_bits_va, *leaf_digest, *root_digest, *path_var, ONE, "ml"));
        //merkle_tree_check_read_gadget<FieldT, HashT> ml(pb, tree_depth, address_bits_va, *leaf_digest, *root_digest, path_var, ONE, "ml");

        // generate constraints
        //root_digest.generate_r1cs_constraints();
        unpacker->generate_r1cs_constraints(true);
        signal->generate_r1cs_constraints();
        signal_variables->generate_r1cs_constraints(); 
        generate_r1cs_equals_const_constraint<FieldT>(pb, ZERO, FieldT::zero(), "ZERO");
        cm_hash->generate_r1cs_constraints(true);
        nullifier_hash->generate_r1cs_constraints(true);
        nullifier->generate_r1cs_constraints();
        external_nullifier -> generate_r1cs_constraints(); 
        path_var->generate_r1cs_constraints();
        ml->generate_r1cs_constraints();
    }

    void writeKeysToFile(char* pk , char* vk) {
        r1cs_constraint_system<FieldT> constraints = this->pb.get_constraint_system();

        r1cs_ppzksnark_keypair<libff::alt_bn128_pp> keypair = generateKeypair(this->pb.get_constraint_system());

        //save keys
        vk2json(keypair, vk);

        writeToFile(pk, keypair.pk);
        writeToFile("zksnark_element/vk.raw", keypair.vk); 
    }

    r1cs_ppzksnark_proof<libff::alt_bn128_pp> prove(std::vector<merkle_authentication_node> path, int address, libff::bit_vector address_bits , 
                libff::bit_vector _nullifier , libff::bit_vector secret , libff::bit_vector root,
                libff::bit_vector _signal, libff::bit_vector _signal_variables, libff::bit_vector _external_nullifier , 
                int fee, char* pk , bool isInt)
    { 

        cm->generate_r1cs_witness(_nullifier);
        sk->generate_r1cs_witness(secret);
        signal->generate_r1cs_witness(_signal);
        signal_variables->generate_r1cs_witness(_signal_variables);
        nullifier->generate_r1cs_witness(_external_nullifier);

        cm_hash->generate_r1cs_witness();  
        external_nullifier -> generate_r1cs_witness(_external_nullifier);
        nullifier_hash->generate_r1cs_witness();
        address_bits_va.fill_with_bits(pb, address_bits);
        assert(address_bits_va.get_field_element_from_bits(pb).as_ulong() == address);
        pb.val(msgSenderFee) = fee;


        path_var->generate_r1cs_witness(address, path);
        ml->generate_r1cs_witness();

        // make sure that read checker didn't accidentally overwrite anything 
        address_bits_va.fill_with_bits(pb, address_bits);
        root_digest->generate_r1cs_witness(root);
        unpacker->generate_r1cs_witness_from_bits();
            
        r1cs_ppzksnark_keypair<libff::alt_bn128_pp> keypair;
        // TODO: verify file exists
        keypair.pk = loadFromFile<r1cs_ppzksnark_proving_key<alt_bn128_pp>> (pk);

        r1cs_primary_input <FieldT> primary_input = pb.primary_input();
        std::cout << "primary_input " << primary_input;
        r1cs_auxiliary_input <FieldT> auxiliary_input = pb.auxiliary_input();
        r1cs_ppzksnark_proof<libff::alt_bn128_pp> proof = r1cs_ppzksnark_prover<libff::alt_bn128_pp>(keypair.pk, primary_input, auxiliary_input);

        return proof;
    }

    bool verify( r1cs_ppzksnark_proof<libff::alt_bn128_pp> proof, r1cs_ppzksnark_verification_key<libff::alt_bn128_pp> vk, r1cs_ppzksnark_primary_input <libff::alt_bn128_pp> primary_input )
    {
        return r1cs_ppzksnark_verifier_strong_IC <libff::alt_bn128_pp> (vk, primary_input, proof);
    }
};

void genKeys(int tree_depth, char* pkOutput, char* vkOuput) {

    libff::alt_bn128_pp::init_public_params();
    Miximus<FieldT, sha256_ethereum> c (tree_depth);
    c.writeKeysToFile(pkOutput, vkOuput );
}

bool verify( char* vk, char* _g_A_0, char* _g_A_1, char* _g_A_2 ,  char* _g_A_P_0, char* _g_A_P_1, char* _g_A_P_2, 
             char* _g_B_1, char* _g_B_0, char* _g_B_3, char* _g_B_2, char* _g_B_5 , char* _g_B_4, char* _g_B_P_0, char* _g_B_P_1, char* _g_B_P_2,
             char* _g_C_0, char* _g_C_1, char* _g_C_2, char* _g_C_P_0, char* _g_C_P_1, char* _g_C_P_2,
             char* _g_H_0, char* _g_H_1, char* _g_H_2, char* _g_K_0, char* _g_K_1, char* _g_K_2, char* _input0 , char* _input1 , char* _input2, char* _input3,
             char* _input4, char* _input5
             ) { 
    //libff::G1<alt_bn128_pp> g_a_0("5");
    libff::bigint<libff::alt_bn128_r_limbs> g_A_0;
    libff::bigint<libff::alt_bn128_r_limbs> g_A_1;
    libff::bigint<libff::alt_bn128_r_limbs> g_A_2;
    libff::bigint<libff::alt_bn128_r_limbs> g_A_P_0;
    libff::bigint<libff::alt_bn128_r_limbs> g_A_P_1;
    libff::bigint<libff::alt_bn128_r_limbs> g_A_P_2;
    libff::bigint<libff::alt_bn128_r_limbs> g_B_0;
    libff::bigint<libff::alt_bn128_r_limbs> g_B_1;
    libff::bigint<libff::alt_bn128_r_limbs> g_B_2;
    libff::bigint<libff::alt_bn128_r_limbs> g_B_3;
    libff::bigint<libff::alt_bn128_r_limbs> g_B_4;
    libff::bigint<libff::alt_bn128_r_limbs> g_B_5;

    libff::bigint<libff::alt_bn128_r_limbs> g_B_P_0;
    libff::bigint<libff::alt_bn128_r_limbs> g_B_P_1;
    libff::bigint<libff::alt_bn128_r_limbs> g_B_P_2;

    libff::bigint<libff::alt_bn128_r_limbs> g_C_0;
    libff::bigint<libff::alt_bn128_r_limbs> g_C_1;
    libff::bigint<libff::alt_bn128_r_limbs> g_C_2;

    libff::bigint<libff::alt_bn128_r_limbs> g_C_P_0;
    libff::bigint<libff::alt_bn128_r_limbs> g_C_P_1;
    libff::bigint<libff::alt_bn128_r_limbs> g_C_P_2;

    libff::bigint<libff::alt_bn128_r_limbs> g_H_0;
    libff::bigint<libff::alt_bn128_r_limbs> g_H_1;
    libff::bigint<libff::alt_bn128_r_limbs> g_H_2;

    libff::bigint<libff::alt_bn128_r_limbs> g_K_0;
    libff::bigint<libff::alt_bn128_r_limbs> g_K_1;
    libff::bigint<libff::alt_bn128_r_limbs> g_K_2;

    typedef bigint<alt_bn128_r_limbs> bigint_r;

    g_A_0 = bigint_r(_g_A_0);
    g_A_1 = bigint_r(_g_A_1);
    g_A_2 = bigint_r(_g_A_2);


    g_A_P_0 = bigint_r(_g_A_P_0);
    g_A_P_1 = bigint_r(_g_A_P_1);
    g_A_P_2 = bigint_r(_g_A_P_2);

    g_B_0 = bigint_r(_g_B_0);
    g_B_1 = bigint_r(_g_B_1);
    g_B_2 = bigint_r(_g_B_2);
    g_B_3 = bigint_r(_g_B_3);
    g_B_4 = bigint_r(_g_B_4);
    g_B_5 = bigint_r(_g_B_5);


    g_B_P_0 = bigint_r(_g_B_P_0);
    g_B_P_1 = bigint_r(_g_B_P_1);
    g_B_P_2 = bigint_r(_g_B_P_2);

    g_C_0 = bigint_r(_g_C_0);
    g_C_1 = bigint_r(_g_C_1);
    g_C_2 = bigint_r(_g_C_2);

    g_C_P_0 = bigint_r(_g_C_P_0);
    g_C_P_1 = bigint_r(_g_C_P_1);
    g_C_P_2 = bigint_r(_g_C_P_2);

    g_H_0 = bigint_r(_g_H_0);
    g_H_1 = bigint_r(_g_H_1);
    g_H_2 = bigint_r(_g_H_2);

    g_K_0 = bigint_r(_g_K_0);
    g_K_1 = bigint_r(_g_K_1);
    g_K_2 = bigint_r(_g_K_2);

    libff::alt_bn128_G1 g1_A(g_A_0, g_A_1, g_A_2);
    libff::alt_bn128_G1 g1_A_P(g_A_P_0, g_A_P_1, g_A_P_2);

    libff::alt_bn128_Fq2 g_B_0_fq2 (g_B_0, g_B_1);
    libff::alt_bn128_Fq2 g_B_1_fq2 (g_B_2, g_B_3);
    libff::alt_bn128_Fq2 g_B_2_fq2 (g_B_4, g_B_5);

    libff::alt_bn128_G2 g2_B( g_B_0_fq2, g_B_1_fq2, g_B_2_fq2);
    libff::alt_bn128_G1 g1_B_P(g_B_P_0, g_B_P_1, g_B_P_2);

    libff::alt_bn128_G1 g1_C(g_C_0, g_C_1, g_C_2);
    libff::alt_bn128_G1 g1_C_P(g_C_P_0, g_C_P_1, g_C_P_2);

    libff::alt_bn128_G1 g1_H(g_H_0, g_H_1, g_H_2);
    libff::alt_bn128_G1 g1_K(g_K_0, g_K_1, g_K_2);

    std::cout <<"g2_B " << g2_B; 
    
    knowledge_commitment<libff::alt_bn128_G1, libff::alt_bn128_G1 > g_A(g1_A, g1_A_P);
    knowledge_commitment<libff::alt_bn128_G2, libff::alt_bn128_G1 > g_B(g2_B, g1_B_P);
    knowledge_commitment<libff::alt_bn128_G1, libff::alt_bn128_G1 > g_C(g1_C, g1_C_P);

    r1cs_ppzksnark_proof<libff::alt_bn128_pp> proof = r1cs_ppzksnark_proof<libff::alt_bn128_pp>(std::move(g_A), std::move(g_B), std::move(g_C), std::move(g1_H), std::move(g1_K));
  
    r1cs_ppzksnark_primary_input <libff::alt_bn128_pp> primary_input(0, 5);

    primary_input.resize(6);
    primary_input[0] = bigint_r(_input0);
    primary_input[1] = bigint_r(_input1);
    primary_input[2] = bigint_r(_input2);
    primary_input[3] = bigint_r(_input3);
    primary_input[4] = bigint_r(_input4);
    primary_input[5] = bigint_r(_input5);


    r1cs_ppzksnark_keypair<libff::alt_bn128_pp> keypair;
    // TODO: verify file exists
    keypair.vk = loadFromFile<r1cs_ppzksnark_verification_key<libff::alt_bn128_pp>> (vk);

    /*
    r1cs_ppzksnark_proof<libff::alt_bn128_pp> proof1 = loadFromFile<r1cs_ppzksnark_proof<libff::alt_bn128_pp>> ("zksnark_element/proof.raw");
    r1cs_ppzksnark_primary_input <libff::alt_bn128_pp> primary_input1(0, 5);

    std::cout  << "output " << std::endl << outputPointG2AffineAsHex(proof.g_B.g) << std::endl << outputPointG2AffineAsHex(proof1.g_B.g) << std::endl;
    bool test = proof == proof1;
    bool test0 = proof.g_A.g == proof1.g_A.g;
    bool test1 = proof.g_A.h == proof1.g_A.h;
    bool test2 = proof.g_B.g == proof1.g_B.g;
    bool test3 = proof.g_A.h == proof1.g_A.h;
    bool test4 = proof.g_C.g == proof1.g_C.g;
    bool test5 = proof.g_C.h == proof1.g_C.h;
    bool test6 = proof.g_H == proof1.g_H;
    bool test7 = proof.g_K == proof1.g_K;
 
    std::cout << " test out " << test << test0 << test1 << test2<< test3<<test4<<test5<<test6<<test7;
    */

    return r1cs_ppzksnark_verifier_strong_IC <libff::alt_bn128_pp> (keypair.vk, primary_input, proof);
}

char* prove(bool _path[][256], bool _signal[256], bool _signal_variables[256] , bool _external_nullifier[256],  int _address, bool _address_bits[], int tree_depth, int fee, char* pk, bool isInt) { 

    libff::alt_bn128_pp::init_public_params();
    libff::bit_vector init(0,256);
    libff::bit_vector _nullifier(0,256);
    libff::bit_vector _secret(0, 256);
    libff::bit_vector _root(0,256);
    libff::bit_vector signal(0,256);
    libff::bit_vector signal_variables(0,256);
    libff::bit_vector external_nullifier(0,256);

    libff::bit_vector address_bits;

    std::vector<merkle_authentication_node> path(tree_depth);

    init.resize(256);

    path.resize(tree_depth);
    _nullifier.resize(256);    
    _secret.resize(256);
    _root.resize(256);
    signal.resize(256);
    signal_variables.resize(256);
    external_nullifier.resize(256);

    std::cout << "tree depth: " << tree_depth << std::endl;
    for (int i =tree_depth - 1; i>=0 ; i--) {
        path[i] = init;
        for (int j =0; j<sizeof(_path[0]); j++) {
            path[i][j] = _path[i][j];
       }
    }

    for (int j = 0 ; j <256 ; j++) { 
        _nullifier[j] = _path[tree_depth][j];
        _secret[j] = _path[tree_depth+1][j];
        _root[j] = _path[tree_depth + 2][j];
        signal[j] = _signal[j];
        signal_variables[j] = _signal_variables[j]; 
        external_nullifier[j] = _external_nullifier[j];
    }

    size_t address = 0;
    for (long level = tree_depth-1; level >= 0; level--)
    {
        const bool computed_is_right = _address_bits[level];
        address |= (computed_is_right ? 1ul << (tree_depth-1-level) : 0);
        address_bits.push_back(computed_is_right);
    }

    libff::alt_bn128_pp::init_public_params();
    Miximus<FieldT, sha256_ethereum> c(tree_depth);

    auto out = c.prove(path, address , address_bits, _nullifier, _secret, _root, signal, signal_variables, external_nullifier, fee, pk, isInt);

    auto json = proof_to_json (out, c.pb.primary_input(), isInt);     

    auto result = new char[json.size()];
    memcpy(result, json.c_str(), json.size() + 1);     
    return result; 
}

