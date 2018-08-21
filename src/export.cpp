/*    
    copyright 2018 to the Semaphore Authors

    This file is part of Semaphore.

    Semaphore is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Semaphore is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Semaphore.  If not, see <https://www.gnu.org/licenses/>.
*/

#include <fstream>
#include <iostream>
#include <cassert>
#include <iomanip>



#include "r1cs_gg_ppzksnark_zok/r1cs_gg_ppzksnark_zok.hpp"

// ZoKrates
#include "ZoKrates/wraplibsnark.cpp"

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

#include <libsnark/gadgetlib1/gadget.hpp>


using namespace libsnark;
using namespace libff;


template<typename ppT>
string proof_to_json(r1cs_gg_ppzksnark_zok_proof<ppT> &proof, r1cs_primary_input<libff::Fr<ppT>> &input) {
    std::stringstream ss;

    ss << "{\n";
    ss << " \"A\" :[" << outputPointG1AffineAsHex(proof.g_A) << "],\n";
    ss << " \"B\"  :[" << outputPointG2AffineAsHex(proof.g_B)<< "],\n";
    ss << " \"C\"  :[" << outputPointG1AffineAsHex(proof.g_C)<< "],\n";
    ss << " \"input\" :" << "["; //1 should always be the first variavle passed

    for (size_t i = 0; i < input.size(); ++i)
    {   
        ss << "\"0x" << HexStringFromLibsnarkBigint(input[i].as_bigint()) << "\""; 
        if ( i < input.size() - 1 ) { 
            ss<< ", ";
        }
    }
    ss << "]\n";
    ss << "}";

    ss.rdbuf()->pubseekpos(0, std::ios_base::out);

    return(ss.str());
}

template<typename ppT>
std::string vk2json(r1cs_gg_ppzksnark_zok_verification_key<ppT> &vk )
{
    std::stringstream ss;
    unsigned icLength = vk.gamma_ABC_g1.rest.indices.size() + 1;
    
    ss << "{\n";
    ss << " \"alpha\" :[" << outputPointG1AffineAsHex(vk.alpha_g1) << "],\n";
    ss << " \"beta\"  :[" << outputPointG2AffineAsHex(vk.beta_g2) << "],\n";
    ss << " \"gamma\" :[" << outputPointG2AffineAsHex(vk.gamma_g2) << "],\n";
    ss << " \"delta\" :[" << outputPointG2AffineAsHex(vk.delta_g2)<< "],\n";

    ss <<  "\"gammaABC\" :[[" << outputPointG1AffineAsHex(vk.gamma_ABC_g1.first) << "]";
    
    for (size_t i = 1; i < icLength; ++i)
    {   
        auto vkICi = outputPointG1AffineAsHex(vk.gamma_ABC_g1.rest.values[i - 1]);
        ss << ",[" <<  vkICi << "]";
    } 
    ss << "]";
    ss << "}";
    return ss.str();
}


template<typename ppT>
void vk2json_file(r1cs_gg_ppzksnark_zok_verification_key<ppT> &vk, std::string path )
{
    std::ofstream fh;
    fh.open(path, std::ios::binary);
    fh << vk2json(vk);
    fh.flush();
    fh.close();
}
