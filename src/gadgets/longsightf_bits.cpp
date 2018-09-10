#include <libsnark/gadgetlib1/gadgets/hashes/hash_io.hpp> // digest_variable
#include <libsnark/common/data_structures/merkle_tree.hpp>

using libsnark::packing_gadget;
using libsnark::digest_variable;
using libsnark::block_variable;
using libsnark::merkle_authentication_path;
using libsnark::multipacking_gadget;


#include "ethsnarks.hpp"
#include "utils.hpp"


namespace ethsnarks {

/**
* LongsightF gadget, but with input and output in bits
*
* With the 'bitness' check it requires an additional 764 constraints!
*/
template<typename HashT>
class LongsightF_bits_gadget : public GadgetT
{
public:
    const VariableT left_element{make_variable(this->pb, FMT(this->annotation_prefix, " left_element"))};
    const VariableT right_element{make_variable(this->pb, FMT(this->annotation_prefix, " right_element"))};

    const std::vector<VariableT> packer_vars1{left_element, right_element};
    const VariableArrayT packer_vars2{packer_vars1.begin(), packer_vars1.end()};
    multipacking_gadget<FieldT> left_right_packer;

    HashT hasher{this->pb, left_element, right_element, FMT(this->annotation_prefix, " hasher")};

    const digest_variable<FieldT>& output_digest;
    packing_gadget<FieldT> output_packer{this->pb, output_digest.bits, hasher.result()};

    typedef libff::bit_vector hash_value_type;
    typedef merkle_authentication_path merkle_authentication_path_type;

    LongsightF_bits_gadget(
        ProtoboardT &in_pb,
        const size_t block_length,
        const block_variable<FieldT> &in_block,
        const digest_variable<FieldT> &out_digest,
        const std::string &in_annotation_prefix=""
    ) :
        GadgetT(in_pb, in_annotation_prefix),
        left_right_packer(in_pb, in_block.bits, packer_vars2, get_digest_len(), FMT(in_annotation_prefix, "left_right_packer")),
        output_digest(out_digest)
    {
        assert( block_length == get_block_len() );
        assert( in_block.block_size == get_block_len() );
    }


    libff::bit_vector get_digest() const
    {
        return output_digest.get_digest();
    }

    static libff::bit_vector get_hash(const libff::bit_vector &input)
    {
        ProtoboardT pb;

        assert( input.size() == get_block_len() );

        block_variable<FieldT> input_block(pb, get_block_len(), "block");
        digest_variable<FieldT> digest_output(pb, get_digest_len(), "digest_output");
        LongsightF_bits_gadget<HashT> the_gadget(pb, get_block_len(), input_block, digest_output);

        input_block.generate_r1cs_witness(input);
        the_gadget.generate_r1cs_witness();

        assert( pb.is_satisfied() );

        return the_gadget.get_digest();
    }

    void generate_r1cs_constraints(const bool enforce_bitness)
    {
        left_right_packer.generate_r1cs_constraints(enforce_bitness);
        hasher.generate_r1cs_constraints();
        output_packer.generate_r1cs_constraints(enforce_bitness);
    }

    void generate_r1cs_witness()
    {
        // bits -> field element
        left_right_packer.generate_r1cs_witness_from_bits();

        hasher.generate_r1cs_witness();

        // field element -> bits
        output_packer.generate_r1cs_witness_from_packed();
    }

    static size_t get_digest_len()
    {
        return FieldT::capacity() + 1;
    }

    static size_t get_block_len()
    {
        return get_digest_len() * 2;
    }
};

// ethsnarks
}
