// Copyright (c) 2018 HarryR
// License: GPL-3.0+

/**
* This module contains stuff for unserialising the verify key and proofs
* from JSON stuff. It's the opposite of 'export.cpp'...
*/

#include <cassert>

#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
#include <libsnark/knowledge_commitment/knowledge_commitment.hpp>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <gmp.h>


namespace pt = boost::property_tree;


/**
* Loads a ppT::Fq_type from a string, allows for integer, hex or binary encoding
* Prefix with 0x for hex and 0b for binary
*/
template<typename FieldT>
FieldT parse_F(std::string &input)
{
    mpz_t value;
    int value_error;

    assert( input != NULL );
    ::mpz_init(value);

    value_error = ::mpz_set_str(value, input.c_str(), 0);
    assert( ! value_error );    // XXX: abort on error?

    FieldT out(value);
    ::mpz_clear(value);

    return out;
}


template<typename ppT>
typename ppT::Fq_type parse_Fq(std::string &input)
{
    return parse_F<typename ppT::Fq_type>(input);
}


/**
* Create a list of F<x> elements from a node in a property tree, in JSON this is:
*
*   "in_key": [N, N, N, ...]
*/
template<typename FieldT>
std::vector<FieldT> create_F_list_from_ptree( pt::ptree &in_tree, const char *in_key )
{
    std::vector<FieldT> elements;

    for( auto& item : in_tree.get_child(in_key) )
    {
        auto element = item.second.get_value<std::string>();

        elements.push_back( parse_F<FieldT>( element ) );
    }

    return elements;
}


/**
* Create a G1 point from X and Y coords (integers or hex as strings)
*
* This assumes the coordinates are affine.
*/
template<typename ppT>
typename ppT::G1_type create_G1(std::string &in_X, std::string &in_Y)
{
    typedef typename ppT::Fq_type Fq_T;
    typedef typename ppT::G1_type G1_T;

    return G1_T(parse_Fq<ppT>(in_X), parse_Fq<ppT>(in_Y), Fq_T("1"));

    // TODO: verify well_formed
}


/**
* Create a G2 point from 512bit big-endian X and Y coords (integers or hex as strings)
*
*   X.c1, X.c0, Y.c1, Y.c0
*
* This assumes the coordinates are affine.
*/
template<typename ppT>
typename ppT::G2_type create_G2(std::string &in_X_c1, std::string &in_X_c0, std::string &in_Y_c1, std::string &in_Y_c0)
{
    typedef typename ppT::Fq_type Fq_T;
    typedef typename ppT::Fqe_type Fq2_T;
    typedef typename ppT::G2_type G2_T;

    return G2_T(
        Fq2_T(parse_Fq<ppT>(in_X_c0), parse_Fq<ppT>(in_X_c1)),
        Fq2_T(parse_Fq<ppT>(in_Y_c0), parse_Fq<ppT>(in_Y_c1)),
        Fq2_T(Fq_T("0"), Fq_T("1")));   // Z is hard-coded, coordinates are affine

    // TODO: verify well_formed
}


/**
* Retrieve all children of a given key as a vector of a given type
*/
template <typename T>
std::vector<T> as_vector(pt::ptree const& in_tree)
{
    std::vector<T> vars;

    for (auto& item : in_tree)
    {
        vars.push_back(item.second.get_value<T>());
    }

    return vars;
}


/**
* Create a G1 element from a node in a property tree, in JSON this is:
*
*   "in_key": ["X", "Y"]
*/
template<typename ppT>
typename ppT::G1_type create_G1_from_ptree( pt::ptree &in_tree, const char *in_key )
{
    auto vars = as_vector<std::string>(in_tree.get_child(in_key));

    assert(vars.size() == 2);

    return create_G1<ppT>(vars[0], vars[1]);
}


/**
* Create a list of G1 points from a node in a property tree, in JSON this is:
*
*   "in_key": [["X", "Y"], ["X", "Y"], ...]
*/
template<typename ppT>
std::vector<typename ppT::G1_type> create_G1_list_from_ptree( pt::ptree &in_tree, const char *in_key )
{
    typedef typename ppT::G1_type G1_T;

    std::vector<G1_T> points;

    for( auto& item : in_tree.get_child(in_key) )
    {
        auto vars = as_vector<std::string>(item.second);

        assert(vars.size() == 2);

        points.push_back( create_G1<ppT>(vars[0], vars[1]) );
    }

    return points;
}



/**
* Create a G2 element from a node in a property tree, in JSON this is:
*
*   "in_key": [["X.c1", "X.c0"], ["Y.c1", "Y.c0"]]
*/
template<typename ppT>
typename ppT::G2_type create_G2_from_ptree( pt::ptree &in_tree, const char *in_key )
{
    std::vector<std::vector<std::string> > items;

    for( auto& item : in_tree.get_child(in_key) )
    {
        auto vars = as_vector<std::string>(item.second);

        assert(vars.size() == 2);

        items.push_back( vars );
    }

    assert(items.size() == 2);

    return create_G2<ppT>(items[0][0], items[0][1],
                         items[1][0], items[1][1]);
}


/**
* Pair which represents a proof and its inputs
*/
template <typename ppT>
using ProofPairType = std::pair< libsnark::r1cs_ppzksnark_primary_input<ppT>, libsnark::r1cs_ppzksnark_proof<ppT> >;


/**
* Parse the witness/proof from a property tree
*   {"a": g1,
*    "a_p": g1,
*    "b": g2,
*    "b_p": g1,
*    "c": g1,
*    "c_p": g1,
*    "h": g1,
*    "k": g1,
*    "input": [N, N, N ...]}
*/
template<typename ppT>
ProofPairType<ppT> proof_from_tree( pt::ptree &in_tree )
{
    typedef const libsnark::knowledge_commitment<libff::G1<ppT>, libff::G1<ppT> > kc_G1G1_T;
    typedef const libsnark::knowledge_commitment<libff::G2<ppT>, libff::G1<ppT> > kc_G2G1_T;

    auto a = create_G1_from_ptree<ppT>(in_tree, "a");       // g_A.g
    auto a_p = create_G1_from_ptree<ppT>(in_tree, "a_p");   // g_A.h
    auto b = create_G2_from_ptree<ppT>(in_tree, "b");       // g_B.g
    auto b_p = create_G1_from_ptree<ppT>(in_tree, "b_p");   // g_B.h
    auto c = create_G1_from_ptree<ppT>(in_tree, "c");       // g_C.g
    auto c_p = create_G1_from_ptree<ppT>(in_tree, "c_p");   // g_C.h
    auto h = create_G1_from_ptree<ppT>(in_tree, "h");       // g_H
    auto k = create_G1_from_ptree<ppT>(in_tree, "k");       // g_K
    auto input = create_F_list_from_ptree<typename ppT::Fp_type>(in_tree, "input");

    auto A = kc_G1G1_T(a, a_p);
    auto B = kc_G2G1_T(b, b_p);
    auto C = kc_G1G1_T(c, c_p);

    libsnark::r1cs_ppzksnark_proof<ppT> proof(std::move(A), std::move(B), std::move(C), std::move(h), std::move(k));

    ProofPairType<ppT> out(input, proof);

    return out;
}


/**
* Parse the witness/proof from a stream of JSON encoded data
*/
template<typename ppT>
ProofPairType<ppT> proof_from_json( std::stringstream &in_json )
{
    pt::ptree root;

    pt::read_json(in_json, root);

    return proof_from_tree<ppT>(root);
}


/**
* Parse the verification key from a property tree
*
*   {"a": g2,
*    "b": g1,
*    "c": g2,
*    "g": g2,
*    "gb1": g1,
*    "gb2": g2,
*    "z": g2,
*    "IC": [g1, g1, g1...]}
*/
template<typename ppT>
libsnark::r1cs_ppzksnark_verification_key<ppT> vk_from_tree( pt::ptree &in_tree )
{
    // Array of IC G1 points
    auto IC = create_G1_list_from_ptree<ppT>(in_tree, "IC");
    auto alphaA_g2 = create_G2_from_ptree<ppT>(in_tree, "a");
    auto alphaB_g1 = create_G1_from_ptree<ppT>(in_tree, "b");
    auto alphaC_g2 = create_G2_from_ptree<ppT>(in_tree, "c");
    auto gamma_g2 = create_G2_from_ptree<ppT>(in_tree, "g");
    auto gamma_beta_g1 = create_G1_from_ptree<ppT>(in_tree, "gb1");
    auto gamma_beta_g2 = create_G2_from_ptree<ppT>(in_tree, "gb2");
    auto rC_Z_g2 = create_G2_from_ptree<ppT>(in_tree, "z");

    // IC must be split into `first` and `rest` for the accumulator
    auto IC_rest = decltype(IC)(IC.begin() + 1, IC.end());
    auto IC_vec = libsnark::accumulation_vector<libff::G1<ppT> >(std::move(IC[0]), std::move(IC_rest));

    return libsnark::r1cs_ppzksnark_verification_key<ppT>(
        alphaA_g2,
        alphaB_g1,
        alphaC_g2,
        gamma_g2,
        gamma_beta_g1,
        gamma_beta_g2,
        rC_Z_g2,
        IC_vec
        );
}


/**
* Parse the verifying key from a stream of JSON encoded data
*/
template<typename ppT>
libsnark::r1cs_ppzksnark_verification_key<ppT> vk_from_json( std::stringstream &in_json )
{
    pt::ptree root;

    pt::read_json(in_json, root);

    return vk_from_tree<ppT>(root);
}

