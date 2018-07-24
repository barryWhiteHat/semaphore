#pragma once

#include <libsnark/gadgetlib1/pb_variable.hpp>

using libsnark::pb_variable_array;
using libsnark::digest_variable;

// Copied from `int_list_to_bits`
libff::bit_vector bytes_to_bv(const uint8_t *in_bytes, const size_t in_count)
{
    libff::bit_vector res(in_count * 8);
    for( size_t i = 0; i < in_count; i++ )
    {
        for( size_t j = 0; j < 8; j++ ) {
            res[i * 8 + j] = in_bytes[i] & (1 << (8 - 1 - j)) ? 1 : 0;
        }
    }
    return res;
}


std::vector<unsigned long> bit_list_to_ints(std::vector<bool> bit_list, const size_t wordsize)
{
    std::vector<unsigned long> res;
    size_t iterations = bit_list.size()/wordsize+1;

    for (size_t i = 0; i < iterations; ++i)
    {
        unsigned long current = 0;
        for (size_t j = 0; j < wordsize; ++j)
        {
            if (bit_list.size() == (i*wordsize+j)) {
                break;
            }

            current += (bit_list[i*wordsize+j] * (1ul<<(wordsize-1-j)));
      }
      res.push_back(current);
    }

    return res;
}


void bv_to_bytes(const libff::bit_vector &in_bits, uint8_t *out_bytes)
{
    for( auto& b : bit_list_to_ints(in_bits, 8) ) {
        *out_bytes++ = (uint8_t)b;
    }
}


template<typename FieldT>
pb_variable_array<FieldT> block_from_left_right (
    const digest_variable<FieldT> &left,
    const digest_variable<FieldT> &right
) {
    pb_variable_array<FieldT> block;
    block.insert(block.end(), left.bits.begin(), left.bits.end());
    block.insert(block.end(), right.bits.begin(), right.bits.end());    
    return block;
}


void print_bv( const char *prefix, const libff::bit_vector &vec )
{
    std::cout << prefix << ": ";
    for (size_t i = 0; i < vec.size(); ++i)
    {
        std::cout << vec[i];
        if( i > 0 && i % 8 == 0 ) {
            std::cout << " ";
        }
    }
    std::cout << "\n";
}
