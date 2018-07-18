#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

namespace pt = boost::property_tree;

template<typename ppT>
libsnark::r1cs_ppzksnark_verification_key<ppT> vk_from_tree( pt::ptree &in_tree )
{
	// Types for G1 points
	typedef libff::alt_bn128_G1 g1_T;
	typedef typename ppT::Fq_type Fq_T;

	// Types for G2 points
	typedef libff::alt_bn128_G2 g2_T;
	typedef typename ppT::Fqe_type Fq2_T;

	/* 'b': [2176926483688270737604805316604149338548240493746606043711627318561627294738,
			 4335753396000479850511244511395459655604643962993127739109076544960626016058,
			 6733379360687434701495634533645959788516357809577212658549681841828052113963,
			 7936470743960650903017393429910639797545189564045419640593553489332135223906,
			 0, 1],
	*/
	auto testg2 = g2_T(
		Fq2_T(Fq_T("4335753396000479850511244511395459655604643962993127739109076544960626016058"), Fq_T("2176926483688270737604805316604149338548240493746606043711627318561627294738")),
		Fq2_T(Fq_T("7936470743960650903017393429910639797545189564045419640593553489332135223906"), Fq_T("6733379360687434701495634533645959788516357809577212658549681841828052113963")),
		Fq2_T(Fq_T("0"), Fq_T("1")));

	// Array of IC G2 points
	// a G2 point
	// b G1 point
	auto b = g1_T(Fq_T("1"), Fq_T("2"), Fq_T("1"));
	// c G2 point
	// g G2 point
	// gb1 G1 point
	auto gb1 = g1_T(Fq_T("1"), Fq_T("2"), Fq_T("1"));
	// gb2 G2 point
	// z G2 point
}

template<typename ppT>
libsnark::r1cs_ppzksnark_verification_key<ppT> vk_from_json( std::string in_json )
{
	pt::ptree root;
	pt::read_json(in_json, root);
	return vk_from_tree<ppT>(root);
}
