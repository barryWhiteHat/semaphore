#include "longsightf.cpp"

#include <libsnark/gadgetlib1/gadgets/hashes/hash_io.hpp> // digest_variable
#include <libsnark/common/data_structures/merkle_tree.hpp>

using libsnark::packing_gadget;
using libsnark::digest_variable;
using libsnark::merkle_authentication_path;

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
    const pb_variable<FieldT> left_element;
    packing_gadget<FieldT> left_packer;

    const pb_variable<FieldT> right_element;
    packing_gadget<FieldT> right_packer;

    HashT hasher;

    const digest_variable<FieldT> output_digest;
    packing_gadget<FieldT> output_packer;

    typedef libff::bit_vector hash_value_type;
    typedef merkle_authentication_path merkle_authentication_path_type;

    LongsightF_bits_gadget(
        protoboard<FieldT> &in_pb,
        const digest_variable<FieldT> &in_left,
        const digest_variable<FieldT> &in_right,
        const std::string &in_annotation_prefix=""
    ) :
        gadget<FieldT>(in_pb, in_annotation_prefix),

        // unpack(left_bits) -> left_element
        left_element(make_variable(in_pb, FMT(in_annotation_prefix, " left_element"))),
        left_packer(in_pb, in_left.bits, left_element),

        // unpack(right_bits) -> right_element
        right_element(make_variable(in_pb, FMT(in_annotation_prefix, " right_element"))),
        right_packer(in_pb, in_right.bits, right_element),

        // hash(left_element, right_element) -> output_element
        hasher(in_pb, left_element, right_element, FMT(in_annotation_prefix, " hasher")),

        // pack(output_element) -> output_digest
        output_digest(in_pb, FieldT::capacity(), FMT(in_annotation_prefix, " output_digest")),
        output_packer(in_pb, output_digest.bits, hasher.result())
    {
        assert( in_left.digest_size == get_digest_len() );
        assert( in_right.digest_size == get_digest_len() );
    }

    libff::bit_vector get_digest() const
    {
        return output_digest.get_digest();
    }

    static libff::bit_vector get_hash(const libff::bit_vector &input)
    {
        protoboard<FieldT> pb;

        digest_variable<FieldT> input_left(pb, get_block_len(), "input_left");
        const libff::bit_vector left_bits(input.begin(), input.begin() + get_digest_len());
        input_left.generate_r1cs_witness(left_bits);

        digest_variable<FieldT> input_right(pb, get_block_len(), "input_right");
        const libff::bit_vector right_bits(input.begin() + get_digest_len(), input.end());
        input_right.generate_r1cs_witness(right_bits);

        LongsightF_bits_gadget<FieldT, HashT> the_gadget(pb, input_left, input_right);
        the_gadget.generate_r1cs_witness();

        return the_gadget.get_digest();
    }

    void generate_r1cs_constraints(const bool enforce_bitness)
    {
        left_packer.generate_r1cs_constraints(enforce_bitness);
        right_packer.generate_r1cs_constraints(enforce_bitness);
        hasher.generate_r1cs_constraints();
        output_packer.generate_r1cs_constraints(enforce_bitness);
    }

    void generate_r1cs_witness()
    {
        // bits -> field element
        left_packer.generate_r1cs_witness_from_bits();
        right_packer.generate_r1cs_witness_from_bits();

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
