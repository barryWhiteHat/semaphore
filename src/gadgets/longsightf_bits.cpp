#include "longsightf.cpp"

#include <libsnark/gadgetlib1/gadgets/hashes/hash_io.hpp> // digest_variable
#include <libsnark/common/data_structures/merkle_tree.hpp>

using libsnark::packing_gadget;
using libsnark::digest_variable;
using libsnark::block_variable;
using libsnark::merkle_authentication_path;
using libsnark::pb_variable_array;
using libsnark::multipacking_gadget;
using libsnark::pb_linear_combination;

/**
* LongsightF gadget, but with input and output in bits
*
* With the 'bitness' check it requires an additional 764 constraints!
*/
template<typename FieldT, typename HashT>
class LongsightF_bits_gadget : public gadget<FieldT>
{
private:
    /* `allocate_var_index` is private, must use this workaround... */
    static pb_variable<FieldT> make_variable( protoboard<FieldT> &in_pb, const std::string &annotation="" )
    {
        pb_variable<FieldT> x;
        x.allocate(in_pb, annotation);
        return x.index;
    }

public:
    const pb_variable<FieldT> left_element{make_variable(this->pb, FMT(this->annotation_prefix, " left_element"))};
    const pb_variable<FieldT> right_element{make_variable(this->pb, FMT(this->annotation_prefix, " right_element"))};

    const std::vector<pb_variable<FieldT> > packer_vars1{left_element, right_element};
    const pb_variable_array<FieldT> packer_vars2{packer_vars1.begin(), packer_vars1.end()};
    multipacking_gadget<FieldT> left_right_packer;

    HashT hasher{this->pb, left_element, right_element, FMT(this->annotation_prefix, " hasher")};

    const digest_variable<FieldT>& output_digest;
    packing_gadget<FieldT> output_packer{this->pb, output_digest.bits, hasher.result()};

    typedef libff::bit_vector hash_value_type;
    typedef merkle_authentication_path merkle_authentication_path_type;

    LongsightF_bits_gadget(
        protoboard<FieldT> &in_pb,
        const size_t block_length,
        const block_variable<FieldT> &in_block,
        const digest_variable<FieldT> &out_digest,
        const std::string &in_annotation_prefix=""
    ) :
        gadget<FieldT>(in_pb, in_annotation_prefix),
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
        protoboard<FieldT> pb;

        assert( input.size() = get_block_len() );

        block_variable<FieldT> input_block(pb, get_block_len(), "block");
        digest_variable<FieldT> digest_output(pb, get_digest_len(), "digest_output");
        LongsightF_bits_gadget<FieldT, HashT> the_gadget(pb, get_block_len(), input_block, digest_output);

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
