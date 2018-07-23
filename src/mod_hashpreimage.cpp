// Copyright (c) 2018 HarryR
// License: LGPL-3.0+

#include "sha256/sha256_full_gadget.cpp"
#include "sha256/utils.cpp"

#include <libff/algebra/fields/field_utils.hpp>

template<typename FieldT>
pb_variable_array<FieldT> pb_variable_array_allocate( protoboard<FieldT> &in_pb, size_t n, const std::string &annotation_prefix )
{
    pb_variable_array<FieldT> res;
    res.allocate(in_pb, n, annotation_prefix);
    return res;
}


/**
* Verify that SHA256(left,right) == expected
*/
template<typename FieldT>
class mod_hashpreimage : public gadget<FieldT>
{
public:
    const size_t input_size_in_bits = SHA256_block_size;

    const size_t input_size_in_fields;

    pb_variable_array<FieldT> input_as_field_elements;

    block_variable<FieldT> input_block;

    pb_variable_array<FieldT> input_as_bits;

    multipacking_gadget<FieldT> unpacker;

    digest_variable<FieldT> output;

    sha256_full_gadget_512<FieldT> full_hasher;

    mod_hashpreimage(
        protoboard<FieldT> &in_pb,
        const std::string &annotation_prefix
    ) :
        gadget<FieldT>(in_pb, annotation_prefix),

        input_size_in_fields( libff::div_ceil(input_size_in_bits, FieldT::capacity()) ),

        input_as_field_elements(pb_variable_array_allocate<FieldT>(in_pb, input_size_in_fields, FMT(annotation_prefix, "packed_inputs"))),

        input_block(in_pb, SHA256_block_size, FMT(annotation_prefix, "input_block")),

        input_as_bits(input_block.bits.begin(), input_block.bits.end()),

        unpacker(in_pb, input_as_bits, input_as_field_elements, FieldT::capacity(), "unpacker"),

        output(in_pb, SHA256_digest_size, FMT(annotation_prefix, " output")),

        full_hasher(in_pb, input_block, output, FMT(annotation_prefix, " full_hasher"))
    {
        in_pb.set_input_sizes( input_size_in_fields );
    }

    void generate_r1cs_constraints()
    {
        unpacker.generate_r1cs_constraints(true);

        full_hasher.generate_r1cs_constraints();
    }

    void generate_r1cs_witness(
        const libff::bit_vector &in_block,
        const libff::bit_vector &in_expected_bv
    ) {
        input_block.generate_r1cs_witness(in_block);

        full_hasher.generate_r1cs_witness();

        output.generate_r1cs_witness(in_expected_bv);

        unpacker.generate_r1cs_witness_from_bits();
    }

    static r1cs_primary_input<FieldT> make_primary_input(const libff::bit_vector &in_block_bv)
    {
        assert( in_block_bv == SHA256_block_size );

        return libff::pack_bit_vector_into_field_element_vector<FieldT>(in_block_bv);
    }
};
