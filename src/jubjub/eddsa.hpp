/*    
    copyright 2018 to the baby_jubjub_ecc Authors

    This file is part of baby_jubjub_ecc.

    baby_jubjub_ecc is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    baby_jubjub_ecc is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with baby_jubjub_ecc.  If not, see <https://www.gnu.org/licenses/>.
*/

#ifndef JUBJUB_EDDSA_HPP_
#define JUBJUB_EDDSA_HPP_

#include <cassert>
#include <memory>

#include "ethsnarks.hpp"

#include "jubjub/curve.hpp"

#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/hash_io.hpp>                   // digest_variable


namespace ethsnarks {

using libsnark::multipacking_gadget;
using libsnark::block_variable;
using libsnark::digest_variable;

template<typename HashT>
class eddsa : public GadgetT
{
private:
    /* no internal variables */
public:
    VariableT a;
    VariableT d;


    //input variables 
    VariableArrayT pk_x;
    VariableArrayT pk_y;
    VariableT b_x;
    VariableT b_y;
    VariableArrayT r_x;
    VariableArrayT r_y;
    VariableArrayT message;
    VariableArrayT S;

    //intermeidate variables 

    VariableArrayT lhs_x;

    VariableArrayT lhs_y;
    VariableArrayT rhs_mul_x;
    VariableArrayT rhs_mul_y;

    VariableT rhs_x;
    VariableT rhs_y;

    std::shared_ptr <block_variable<FieldT>> encode_point_r_input;
    std::shared_ptr <block_variable<FieldT>> encode_point_pk_input;
    std::shared_ptr <block_variable<FieldT>> encode_points_input;
    std::shared_ptr <block_variable<FieldT>> hint_input;


    std::shared_ptr<digest_variable<FieldT>> encoded_r;
    std::shared_ptr<digest_variable<FieldT>> encoded_pk;
    std::shared_ptr<digest_variable<FieldT>> encoded_points;
    std::shared_ptr<digest_variable<FieldT>> h;
    // gadgets 
    std::shared_ptr<isOnCurve> jubjub_isOnCurve1;
    std::shared_ptr<isOnCurve> jubjub_isOnCurve2;

    std::shared_ptr<pointAddition> jubjub_pointAddition;
    std::shared_ptr<pointMultiplication> jubjub_pointMultiplication_lhs;
    std::shared_ptr<pointMultiplication> jubjub_pointMultiplication_rhs;

    std::shared_ptr<HashT> encode_point_r;
    std::shared_ptr<HashT> encode_point_pk;
    std::shared_ptr<HashT> encode_points;
    std::shared_ptr<HashT> hint;

    std::shared_ptr<libsnark::digest_variable<FieldT>> lhs_leaf;

    std::shared_ptr<multipacking_gadget<FieldT>> unpacker_h;
    std::shared_ptr<multipacking_gadget<FieldT>> unpacker_pk_x;
    std::shared_ptr<multipacking_gadget<FieldT>> unpacker_pk_y;
    std::shared_ptr<multipacking_gadget<FieldT>> unpacker_r_x;
    std::shared_ptr<multipacking_gadget<FieldT>> unpacker_r_y;


    VariableArrayT h_packed;
    VariableArrayT h_bits;
    VariableArrayT pk_x_packed;
    VariableArrayT pk_y_packed;
    VariableArrayT r_x_packed;
    VariableArrayT r_y_packed;


    eddsa(
        ProtoboardT &pb,
        //const pb_linear_combination_array<FieldT> &bits,
        const VariableT &a, const VariableT &d,
        const VariableArrayT &pk_x, const VariableArrayT &pk_y,
        const VariableT &b_x, const VariableT &b_y,
        const VariableArrayT &r_x, const VariableArrayT &r_y,
        const VariableArrayT &message, const VariableArrayT &S
    );

    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

// namespace ethsnarks
}

#include "jubjub/eddsa.tcc"

// JUBJUB_EDDSA_HPP_
#endif
