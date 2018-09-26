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

#include "jubjub/pedersen_commitment.hpp"


namespace ethsnarks
{


pedersen_commitment::pedersen_commitment(
    ProtoboardT &pb,
    //const pb_linear_combination_array<FieldT> &bits,
    const VariableT &a, const VariableT &d,
    const VariableT &base_x, const VariableT &base_y,
    const VariableT &H_x, const VariableT &H_y,
    const VariableT &commitment_x, const VariableT &commitment_y,

    const VariableArrayT &m, const VariableArrayT &r
) :
    GadgetT(pb, " pedersen_commitment"),
    a(a), d(d),
    base_x(base_x), base_y(base_y),
    H_x(H_x), H_y(H_y),
    commitment_x(commitment_x),
    commitment_y(commitment_y),
    m(m), r(r)
{
    lhs_x.allocate(pb, 253,  FMT("lhs x", " pedersen_commitment"));
    lhs_y.allocate(pb, 253, FMT("lhs y", " pedersen_commitment"));
    rhs_mul_x.allocate(pb,253, FMT( "rhs mul x" , " pedersen_commitment" ));
    rhs_mul_y.allocate(pb,253, FMT( "rhs mul y ", " pedersen_commitment"));
    rhs_x.allocate(pb,253, FMT( "rhs mul x" , " pedersen_commitment" ));
    rhs_y.allocate(pb,253, FMT( "rhs mul y ", " pedersen_commitment"));

    res_x.allocate(pb, "x_zero");
    res_y.allocate(pb, "y_zero");

    // make sure both points are on the twisted edwards cruve
    jubjub_isOnCurve1.reset( new isOnCurve (pb, base_x,base_y, a, d, "Confirm x, y is on the twiseted edwards curve"));
    jubjub_isOnCurve2.reset( new isOnCurve (pb, H_x, H_y, a, d, "Confirm x, y is on the twiseted edwards curve"));

    // base * m
    jubjub_pointMultiplication_lhs.reset( new pointMultiplication (pb, a, d, base_x, base_y, m, lhs_x, lhs_y, " lhs check ", 253));
    // h*r
    jubjub_pointMultiplication_rhs.reset( new pointMultiplication (pb, a, d, H_x, H_y, r, rhs_x, rhs_y, "rhs mul ", 253));
    jubjub_pointAddition.reset( new pointAddition (pb, a, d, rhs_x[252], rhs_y[252] , lhs_x[252] , lhs_y[252], res_x, res_y , "rhs addition"));
}



void pedersen_commitment::generate_r1cs_constraints()
{
    // not sure if we need to check pub key and r 
    // are on the curve. But doing it here for defense
    // in depth
    jubjub_isOnCurve1->generate_r1cs_constraints();
    jubjub_isOnCurve2->generate_r1cs_constraints();

    jubjub_pointMultiplication_lhs->generate_r1cs_constraints();
    jubjub_pointMultiplication_rhs->generate_r1cs_constraints();
    jubjub_pointAddition->generate_r1cs_constraints();

    this->pb.add_r1cs_constraint(ConstraintT({res_x} , {1}, {commitment_x}),
                           FMT("find y1*x2 == y1x2", " pedersen_commitment"));
    this->pb.add_r1cs_constraint(ConstraintT({res_y} , {1}, {commitment_y}),
                           FMT("find y1*x2 == y1x2", " pedersen_commitment"));
}


void  pedersen_commitment::generate_r1cs_witness()
{
    jubjub_isOnCurve1->generate_r1cs_witness();
    jubjub_isOnCurve2->generate_r1cs_witness();
    jubjub_pointMultiplication_lhs->generate_r1cs_witness();
    jubjub_pointMultiplication_rhs->generate_r1cs_witness();
    jubjub_pointAddition->generate_r1cs_witness();


    //debug
    /*
    std::cout <<  this->pb.lc_val(lhs_x[252]) << " " <<  this->pb.lc_val(rhs_x) << " "<< std::endl; // <<  this->pb.lc_val(S) << " " <<  this->pb.lc_val(H) ;
    for (uint i = 0 ; i < 253; i++) { 
        std::cout << i << " i  " << this->pb.lc_val(S[i]) << std::endl;
    }*/
}

// namespace ethsnarks
}
