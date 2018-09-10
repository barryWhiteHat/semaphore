#ifndef ETHSNARKS_UTILS_HPP_
#define ETHSNARKS_UTILS_HPP_

#include <fstream>

#include "ethsnarks.hpp"

namespace ethsnarks {


void print_bytes( const char *prefix, const size_t n_bytes, const uint8_t *in_bytes );

void print_bv( const char *prefix, const libff::bit_vector &vec );

void bv_to_bytes(const libff::bit_vector &in_bits, uint8_t *out_bytes);

bool hex_to_bytes( const char *in_hex, uint8_t *out_bytes, size_t out_sz );

int char2int( const char input );

std::vector<unsigned long> bit_list_to_ints(std::vector<bool> bit_list, const size_t wordsize);

libff::bit_vector bytes_to_bv(const uint8_t *in_bytes, const size_t in_count);

VariableArrayT VariableArray_from_bits( ProtoboardT &in_pb, const libff::bit_vector& bits, const std::string annotation_prefix="" );

const VariableT make_variable( ProtoboardT &in_pb, const std::string &annotation="" );

const VariableArrayT make_var_array( ProtoboardT &in_pb, size_t n, const std::string &annotation="" );


template<typename T>
void writeToFile(std::string path, T& obj) {
    std::stringstream ss;
    ss << obj;
    std::ofstream fh;
    fh.open(path, std::ios::binary);
    ss.rdbuf()->pubseekpos(0, std::ios_base::out);
    fh << ss.rdbuf();
    fh.flush();
    fh.close();
}


template<typename T>
T loadFromFile(std::string path) {
    std::stringstream ss;
    std::ifstream fh(path, std::ios::binary);

    // TODO: more useful error if file not found
    assert(fh.is_open());

    ss << fh.rdbuf();
    fh.close();

    ss.rdbuf()->pubseekpos(0, std::ios_base::in);

    T obj;
    ss >> obj;

    return obj;
}


// namespace ethsnarks
}

#endif
