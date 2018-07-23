// Copyright (c) 2018 HarryR
// License: LGPL-3.0+

#include <libsnark/gadgetlib1/gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/hash_io.hpp>                   // digest_variable
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_components.hpp>  // SHA256_default_IV
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>      // sha256_compression_function_gadget

using namespace libsnark;


/**
* begin with the original message of length L bits
* append a single '1' bit
* append K '0' bits, where K is the minimum number >= 0 such that L + 1 + K + 64 is a multiple of 512
* append L as a 64-bit big-endian integer, making the total post-processed length a multiple of 512 bits
*
* So given a 512bit message, the _final_padding_512 is another block of 512 bits
* which begins with a '1' bit, and ends with a 64bit big-endian number representing '512'
*/
static const libff::bit_vector _final_padding_512 = libff::int_list_to_bits({
    0x80, 0x00, 0x00, 0x00,    // 4
    0x00, 0x00, 0x00, 0x00,    // 8
    0x00, 0x00, 0x00, 0x00,    // 12
    0x00, 0x00, 0x00, 0x00,    // 16
    0x00, 0x00, 0x00, 0x00,    // 20
    0x00, 0x00, 0x00, 0x00,    // 24
    0x00, 0x00, 0x00, 0x00,    // 28
    0x00, 0x00, 0x00, 0x00,    // 32

    0x00, 0x00, 0x00, 0x00,    // 4
    0x00, 0x00, 0x00, 0x00,    // 8
    0x00, 0x00, 0x00, 0x00,    // 12
    0x00, 0x00, 0x00, 0x00,    // 16
    0x00, 0x00, 0x00, 0x00,    // 20
    0x00, 0x00, 0x00, 0x00,    // 24


    // Remaining 64 bits are the length specifier
    /*
    * bitlen >> 56, bitlen >> 48, bitlen >> 40, bitlen >> 32,
    * bitlen >> 24, bitlen >> 16, bitlen >> 8, bitlen
    */
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x02, 0x00}, 8);


/**
* Convert a bit vector to a pb_variable_array
*/
template<typename FieldT>
pb_variable_array<FieldT> pb_variable_array_from_bits(
    protoboard<FieldT> &in_pb,
    const libff::bit_vector& bits,
    const std::string annotation_prefix )
{
    pb_variable_array<FieldT> out;
    out.allocate(in_pb, bits.size(), annotation_prefix);
    out.fill_with_bits(in_pb, bits);
    return out;
}


/**
* Perform full round of SHA-256 on a 512 bit input
*/
template<typename FieldT>
class sha256_full_gadget_512 : public gadget<FieldT>
{
public:
    digest_variable<FieldT> intermediate_hash;
    sha256_compression_function_gadget<FieldT> input_hasher;
    const pb_variable_array<FieldT> length_padding;
    sha256_compression_function_gadget<FieldT> final_hasher;

    sha256_full_gadget_512(
        protoboard<FieldT> &in_pb,
        const block_variable<FieldT> &input_block,
        const digest_variable<FieldT> &output,
        const std::string &annotation_prefix
    ) :
        gadget<FieldT>(in_pb, FMT(annotation_prefix, "sha256_full_gadget_512")),

        intermediate_hash(in_pb, SHA256_digest_size, FMT(annotation_prefix, " intermediate_hash")),

        input_hasher(in_pb,
                     SHA256_default_IV(in_pb),  // prev_output
                     input_block.bits,          // new_block
                     intermediate_hash,         // output
                     FMT(annotation_prefix, " input_hasher")),

        length_padding(pb_variable_array_from_bits<FieldT>(in_pb, _final_padding_512, FMT(annotation_prefix, " length_padding"))),

        final_hasher(in_pb,
                     intermediate_hash.bits,    // prev_output
                     length_padding,            // new_block
                     output,                    // output
                     FMT(annotation_prefix, " final_hasher"))
    {
        assert( input_block.size() == 512 );
    }

    void generate_r1cs_constraints()
    {
        input_hasher.generate_r1cs_constraints();
        final_hasher.generate_r1cs_constraints();
    }

    void generate_r1cs_witness() {
        input_hasher.generate_r1cs_witness();
        final_hasher.generate_r1cs_witness();
    }
};
