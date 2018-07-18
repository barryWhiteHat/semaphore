#include <cassert>

#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <gmp.h>


namespace pt = boost::property_tree;


/**
* Loads a ppT::Fq_type from a string, allows for integer, hex or binary encoding
* Prefix with 0x for hex and 0b for binary
*/
template<typename ppT>
typename ppT::Fq_type parse_Fq(const char *input)
{
	assert( input != NULL );

	mpz_t value;
	int value_error;

	::mpz_init(value);
	value_error = ::mpz_set_str(value, input, 0);
	assert( ! value_error );	// XXX: abort on error?
	typename ppT::Fq_type out(value);
	::mpz_clear(value);

	return out;
}


/**
* Create a G1 point from X and Y coords (integers or hex as strings)
*
* This assumes the coordinates are affine.
*/
template<typename ppT>
typename ppT::G1_type create_G1(const char *in_X, const char *in_Y)
{
	typedef typename ppT::Fq_type Fq_T;
	typedef typename ppT::G1_type G1_T;

	return G1_T(parse_Fq<ppT>(in_X), parse_Fq<ppT>(in_Y), Fq_T("1"));
}


/**
* Create a G2 point from 512bit big-endian X and Y coords (integers or hex as strings)
*
* 	X.c1, X.c0, Y.c1, Y.c0
*
* This assumes the coordinates are affine.
*/
template<typename ppT>
typename ppT::G2_type create_G2(const char *in_X_c1, const char *in_X_c0, const char *in_Y_c1, const char *in_Y_c0)
{
	typedef typename ppT::Fq_type Fq_T;
	typedef typename ppT::Fqe_type Fq2_T;
	typedef typename ppT::G2_type G2_T;

	return G2_T(
		Fq2_T(parse_Fq<ppT>(in_X_c0), parse_Fq<ppT>(in_X_c1)),
		Fq2_T(parse_Fq<ppT>(in_Y_c0), parse_Fq<ppT>(in_Y_c1)),
		Fq2_T(Fq_T("0"), Fq_T("1")));	// Z is hard-coded, coordinates are affine
}


/**
* Retrieve all children of a given key as a vector of a given type
*/
template <typename T>
std::vector<T> as_vector(pt::ptree const& in_tree)
{
	std::vector<T> vars;

	for (auto& item : in_tree) {
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

	return create_G1<ppT>(vars[0].c_str(), vars[1].c_str());
}


/**
* Create a list of G1 elements from a node in a property tree, in JSON this is:
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

		points.push_back( create_G1<ppT>(vars[0].c_str(), vars[1].c_str()) );
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

	return create_G2<ppT>(items[0][0].c_str(), items[0][1].c_str(),
						 items[1][0].c_str(), items[1][1].c_str());
}


/**
* Parse the verification key from a property tree
*
*	{"a": [g2...],
*    "b": [g1...],
*	 "c": [g2...],
*	 "g": [g2...],
*	 "gb1": [g1...],
*	 "gb2": [g2...],
*    "z": [g2...],
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

	auto IC_rest = decltype(IC)(IC.begin() + 1, IC.end());

	// TODO: split into `first` and `rest`?
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


template<typename ppT>
libsnark::r1cs_ppzksnark_verification_key<ppT> vk_from_json( std::stringstream &in_json )
{
	pt::ptree root;
	pt::read_json(in_json, root);
	return vk_from_tree<ppT>(root);
}

