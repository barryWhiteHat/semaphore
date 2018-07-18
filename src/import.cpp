#include <cassert>

#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>


namespace pt = boost::property_tree;


/**
* Create a G1 point from X and Y coords (integers as strings)
*
* This assumes the coordinates are affine.
*/
template<typename ppT>
typename ppT::G1_type create_G1(const char *in_X, const char *in_Y)
{
	// This assumes the coordinates are affine
	typedef typename ppT::Fq_type Fq_T;
	typedef typename ppT::G1_type G1_T;
	return G1_T(Fq_T(in_X), Fq_T(in_Y), Fq_T("1"));
}


/**
* Create a G2 point from 512bit big-endian X and Y coords (integers as strings)
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
		Fq2_T(Fq_T(in_X_c0), Fq_T(in_X_c1)),
		Fq2_T(Fq_T(in_Y_c0), Fq_T(in_Y_c1)),
		Fq2_T(Fq_T("0"), Fq_T("1")));
}


/**
* Retrieve all children of a given key as a vector of a given type
*/
template <typename T>
std::vector<T> as_vector(pt::ptree const& in_tree, pt::ptree::key_type const& in_key)
{
	std::vector<T> vars;
	for (auto& item : in_tree)
		vars.push_back(item.second.get_value<T>());
	return vars;
}


template<typename ppT>
typename ppT::G1_type create_G1_from_ptree( pt::ptree &in_tree, const char *in_key )
{
	auto vars = as_vector<std::string>(in_tree, in_key);
	assert(vars.size() >= 2);
	return create_G1<ppT>(vars[0].c_str(), vars[1].c_str());
}


template<typename ppT>
typename ppT::G2_type create_G2_from_ptree( pt::ptree &in_tree, const char *in_key )
{
	auto vars = as_vector<std::string>(in_tree, in_key);
	assert(vars.size() >= 4);
	return create_G2<ppT>(vars[0].c_str(), vars[1].c_str(), vars[2].c_str(), vars[3].c_str());
}


template<typename ppT>
libsnark::r1cs_ppzksnark_verification_key<ppT> vk_from_tree( pt::ptree &in_tree )
{
	// Array of IC G2 points

	auto alphaA_g2 = create_G2_from_ptree<ppT>(in_tree, "a");
	auto alphaB_g1 = create_G1_from_ptree<ppT>(in_tree, "b");
	auto alphaC_g2 = create_G2_from_ptree<ppT>(in_tree, "c");
	auto gamma_g2 = create_G2_from_ptree<ppT>(in_tree, "g");
	auto gamma_beta_g1 = create_G1_from_ptree<ppT>(in_tree, "gb1");
	auto gamma_beta_g2 = create_G2_from_ptree<ppT>(in_tree, "gb2");
	auto rC_Z_g2 = create_G2_from_ptree<ppT>(in_tree, "z");
}


template<typename ppT>
libsnark::r1cs_ppzksnark_verification_key<ppT> vk_from_json( std::stringstream &in_json )
{
	pt::ptree root;
	pt::read_json(in_json, root);
	return vk_from_tree<ppT>(root);
}

