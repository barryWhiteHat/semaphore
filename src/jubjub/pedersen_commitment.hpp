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
#ifndef JUBJUB_PEDERSEN_HPP_
#define JUBJUB_PEDERSEN_HPP_

#include <cassert>
#include <memory>

#include "ethsnarks.hpp"
#include "jubjub/curve.hpp"

namespace ethsnarks {


class  pedersen_commitment : public GadgetT {

private:
    /* no internal variables */
public:

    VariableT a;
    VariableT d;

    //input variables 
    VariableT base_x;
    VariableT base_y;
    VariableT H_x;
    VariableT H_y;
    VariableT commitment_x;
    VariableT commitment_y;
    VariableArrayT m;
    VariableArrayT r;

    // Intermediate variables
    VariableT r_x;
    VariableT r_y;
    VariableT s_x;
    VariableT s_y;

    // More intermediate variables
    VariableT res_x;
    VariableT res_y;

    VariableArrayT lhs_x;

    VariableArrayT lhs_y;
    VariableArrayT rhs_mul_x;
    VariableArrayT rhs_mul_y;

    VariableArrayT rhs_x;
    VariableArrayT rhs_y;

    std::shared_ptr<isOnCurve> jubjub_isOnCurve1;
    std::shared_ptr<isOnCurve> jubjub_isOnCurve2;

    std::shared_ptr<pointAddition> jubjub_pointAddition;
    std::shared_ptr<pointMultiplication> jubjub_pointMultiplication_lhs;
    std::shared_ptr<pointMultiplication> jubjub_pointMultiplication_rhs;


     pedersen_commitment(ProtoboardT &pb,
                   //const pb_linear_combination_array<FieldT> &bits,
                   const VariableT &a, const VariableT &d,
                   const VariableT &base_x, const VariableT &base_y,
                   const VariableT &H_x, const VariableT &H_y,
                   const VariableT &commitment_x, const VariableT &commitment_y,
                   const VariableArrayT &m, const VariableArrayT &r
                   );

    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

// namespace ethsnarks
}

// JUBJUB_PEDERSEN_HPP_
#endif
