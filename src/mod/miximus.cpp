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

#include "miximus.hpp"
#include "export.hpp"
#include "import.cpp"
#include "stubs.hpp"
#include "utils.hpp"

#include "gadgets/longsightf.cpp"
#include "gadgets/longsightf_bits.cpp"

#include <libff/algebra/fields/field_utils.hpp>

#include <libsnark/common/data_structures/merkle_tree.hpp>
#include <libsnark/gadgetlib1/gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_authentication_path_variable.hpp>
#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_read_gadget.hpp>

using libsnark::pb_variable;
using libsnark::protoboard;
using libsnark::merkle_authentication_path_variable;
using libsnark::merkle_tree_check_read_gadget;
using libsnark::merkle_authentication_node;
using libsnark::generate_r1cs_equals_const_constraint;
using libff::convert_field_element_to_bit_vector;
using ethsnarks::ppT;
using ethsnarks::FieldT;
using ethsnarks::ProvingKeyT;

const size_t MIXIMUS_TREE_DEPTH = 29;






class mod_miximus : public gadget<FieldT>
{
protected:
    /* `allocate_var_index` is private, must use this workaround... */
    static const pb_variable<FieldT> make_variable( protoboard<FieldT> &in_pb, const std::string &annotation="" )
    {
        pb_variable<FieldT> x;
        x.allocate(in_pb, annotation);
        return x;
    }

    static const pb_variable_array<FieldT> make_var_array( protoboard<FieldT> &in_pb, size_t n, const std::string &annotation="" )
    {
        pb_variable_array<FieldT> x;
        x.allocate(in_pb, n, annotation);
        return x;
    }

    typedef LongsightF322p5_gadget fHashT;
    typedef LongsightF_bits_gadget<FieldT, LongsightF12p5_gadget> bHashT;

public:
    const size_t tree_depth = MIXIMUS_TREE_DEPTH;

    // public inputs
    const pb_variable<FieldT> root_var;
    const pb_variable<FieldT> nullifier_var;
    const pb_variable<FieldT> external_hash_var;

    // private inputs
    const pb_variable<FieldT> ZERO;
    const pb_variable<FieldT> spend_preimage_var;
    const pb_variable_array<FieldT> address_bits;    

    // logic gadgets
    fHashT spend_hash;
    fHashT leaf_hash;
    digest_variable<FieldT> leaf_hash_digest;
    packing_gadget<FieldT> leaf_hash_to_digest;

    digest_variable<FieldT> root_digest;
    packing_gadget<FieldT> root_to_digest;

    merkle_authentication_path_variable<FieldT, bHashT> path_var;
    merkle_tree_check_read_gadget<FieldT, bHashT> check_read;

    mod_miximus(
        protoboard<FieldT> &in_pb,
        const std::string &annotation_prefix
    ) :
        gadget<FieldT>(in_pb, annotation_prefix),

        // public inputs
        root_var(make_variable(in_pb, FMT(annotation_prefix, ".root_var"))),
        nullifier_var(make_variable(in_pb, FMT(annotation_prefix, ".nullifier_var"))),
        external_hash_var(make_variable(in_pb, FMT(annotation_prefix, ".external_hash_var"))),

        // private inputs
        ZERO(make_variable(in_pb, FMT(annotation_prefix, ".ZERO"))),
        spend_preimage_var(make_variable(in_pb, FMT(annotation_prefix, ".spend_preimage_var"))),
        address_bits(make_var_array(in_pb, MIXIMUS_TREE_DEPTH, FMT(annotation_prefix, ".address_bits")) ),

        // logic gadgets
        spend_hash(in_pb, spend_preimage_var, nullifier_var, FMT(annotation_prefix, ".spend_hash")),
        leaf_hash(in_pb, nullifier_var, spend_hash.result(), FMT(annotation_prefix, ".leaf_hash")),
        leaf_hash_digest(in_pb, bHashT::get_digest_len(), FMT(annotation_prefix, ".leaf_hash_digest")),
        leaf_hash_to_digest(in_pb, leaf_hash_digest.bits, leaf_hash.result(), FMT(annotation_prefix, ".leaf_hash_to_digest")),

        root_digest(in_pb, bHashT::get_digest_len(), FMT(annotation_prefix, ".root_digest")),
        root_to_digest(in_pb, root_digest.bits, root_var, FMT(annotation_prefix, ".root_to_digest")),

        path_var(in_pb, tree_depth, ".path"),
        check_read(in_pb, tree_depth, address_bits, leaf_hash_digest, root_digest, path_var, ZERO, ".check_read")
    {
        in_pb.set_input_sizes( 3 );
    }

    void generate_r1cs_constraints()
    {
        generate_r1cs_equals_const_constraint<FieldT>(this->pb, ZERO, FieldT::zero(), "ZERO");

        spend_hash.generate_r1cs_constraints();
        leaf_hash.generate_r1cs_constraints();
        leaf_hash_digest.generate_r1cs_constraints();
        leaf_hash_to_digest.generate_r1cs_constraints(false);

        root_digest.generate_r1cs_constraints();
        root_to_digest.generate_r1cs_constraints(false);

        path_var.generate_r1cs_constraints();
        check_read.generate_r1cs_constraints();
    }

    void generate_r1cs_witness(FieldT in_root, FieldT in_nullifier, FieldT in_exthash, FieldT in_preimage, libff::bit_vector in_address, std::vector<merkle_authentication_node> in_path)
    {
        // public inputs
        this->pb.val(root_var) = in_root;
        this->pb.val(nullifier_var) = in_nullifier;
        this->pb.val(external_hash_var) = in_exthash;

        // private inputs
        this->pb.val(ZERO) = FieldT::zero();
        this->pb.val(spend_preimage_var) = in_preimage;
        address_bits.fill_with_bits(this->pb, in_address);

        size_t tmp_address = address_bits.get_field_element_from_bits(this->pb).as_ulong();
        path_var.generate_r1cs_witness(tmp_address, in_path);

        // gadgets
        spend_hash.generate_r1cs_witness();
        leaf_hash.generate_r1cs_witness();
        leaf_hash_to_digest.generate_r1cs_witness_from_packed();

        root_to_digest.generate_r1cs_witness_from_packed();

        check_read.generate_r1cs_witness();
    }
};


size_t miximus_tree_depth( void ) {
    return MIXIMUS_TREE_DEPTH;
}


char *miximus_prove(
    const char *pk_file,
    const char *in_root,
    const char *in_nullifier,
    const char *in_spend_preimage,
    const char *in_exthash,
    const char *in_address,
    const char **in_path
) {
    ppT::init_public_params();

    FieldT arg_root(in_root);
    FieldT arg_nullifier(in_nullifier);
    FieldT arg_exthash(in_exthash);
    FieldT arg_spend_preimage(in_spend_preimage);

    // Fill address bits with 0s and 1s from str
    libff::bit_vector address_bits;
    address_bits.resize(MIXIMUS_TREE_DEPTH);
    if( strlen(in_address) != MIXIMUS_TREE_DEPTH )
    {
        std::cerr << "Address length doesnt match depth" << std::endl;
        return nullptr;
    }
    for( size_t i = 0; i < MIXIMUS_TREE_DEPTH; i++ ) {
        if( in_address[i] != '0' and in_address[i] != '1' ) {
            std::cerr << "Address bit " << i << " invalid, unknown: " << in_address[i] << std::endl;
            return nullptr;
        }
        address_bits[i] = '0' - in_address[i];
    }

    // Fill path from field elements from in_path
    std::vector<merkle_authentication_node> arg_path;
    arg_path.resize(MIXIMUS_TREE_DEPTH);
    for( size_t i = 0; i < MIXIMUS_TREE_DEPTH; i++ ) {
        assert( in_path[i] != nullptr );
        arg_path[i] = convert_field_element_to_bit_vector<FieldT>(FieldT(in_path[i]));
    }

    protoboard<FieldT> pb;
    mod_miximus mod(pb, "module");
    mod.generate_r1cs_constraints();
    mod.generate_r1cs_witness(arg_root, arg_nullifier, arg_exthash, arg_spend_preimage, address_bits, arg_path);

    if( ! pb.is_satisfied() )
    {
        std::cerr << "Not Satisfied!" << std::endl;
        return nullptr;
    }

    auto proving_key = loadFromFile<ProvingKeyT>(pk_file);
    // TODO: verify if proving key was loaded correctly, if not return NULL

    auto primary_input = pb.primary_input();
    auto proof = libsnark::r1cs_gg_ppzksnark_zok_prover<ppT>(proving_key, primary_input, pb.auxiliary_input());
    auto json = ethsnarks::proof_to_json(proof, primary_input);

    return ::strdup(json.c_str());
}


int miximus_genkeys( const char *pk_file, const char *vk_file )
{
    return ethsnarks::stub_genkeys<mod_miximus>(pk_file, vk_file);
}


bool miximus_verify( const char *vk_json, const char *proof_json )
{
    return ethsnarks::stub_verify( vk_json, proof_json );
}
