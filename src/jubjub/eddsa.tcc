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

#include "jubjub/eddsa.hpp"

namespace ethsnarks {


template<typename HashT>
eddsa<HashT>::eddsa(
    ProtoboardT &pb,
    //const pb_linear_combination_array<FieldT> &bits,
    const VariableT &a, const VariableT &d,
    const VariableArrayT &pk_x, const VariableArrayT &pk_y,
    const VariableT &b_x, const VariableT &b_y,
    const VariableArrayT &r_x, const VariableArrayT &r_y,
    const VariableArrayT &message, const VariableArrayT &S
) :
    GadgetT(pb, "eddsa"),
    a(a), d(d),
    pk_x(pk_x), pk_y(pk_y),
    b_x(b_x), b_y(b_y),
    r_x(r_x), r_y(r_y),
    message(message),
    S(S) 
{
    lhs_x.allocate(pb, 256,  FMT("lhs x", "eddsa"));
    lhs_y.allocate(pb, 256, FMT("lhs y", "eddsa"));
    rhs_mul_x.allocate(pb,256, FMT( "rhs mul x" , "eddsa" ));
    rhs_mul_y.allocate(pb,256, FMT( "rhs mul y ", "eddsa"));

    rhs_x.allocate(pb, FMT("rhs x", "eddsa"));
    rhs_y.allocate(pb, FMT( "rhs y","eddsa"));

    encode_point_r_input.reset(new block_variable<FieldT>(pb, {r_x, r_y}, "encode_point_r_input"));
    encode_point_pk_input.reset(new block_variable<FieldT>(pb, {pk_x, pk_y}, "encode_point_pk_input"));


    encoded_r.reset(new digest_variable<FieldT>(pb, 256, "encoded r"));
    encoded_pk.reset(new digest_variable<FieldT>(pb, 256, "encoded r"));
    h.reset(new digest_variable<FieldT>(pb, 256, "h_bits"));
    encoded_points.reset(new digest_variable<FieldT>(pb, 256, "encoded points"));

    encode_points_input.reset(new block_variable<FieldT>(pb, {encoded_r->bits, encoded_pk->bits}, "encode_points_input"));
    hint_input.reset(new block_variable<FieldT>(pb, {encoded_points->bits, message}, "hint input"));

    encode_point_r.reset(new HashT(pb, *encode_point_r_input, *encoded_r, "encode R"));
    encode_point_pk.reset(new HashT(pb, *encode_point_pk_input, *encoded_pk, "encode pk"));
    encode_points.reset(new HashT(pb, *encode_points_input, *encoded_points, "encode pk"));
    hint.reset(new HashT(pb, *hint_input, *h, "hint"));

    h_packed.allocate(pb,2, "ZERO");

    unpacker_h.reset(new multipacking_gadget<FieldT>(
        pb,
        h->bits, //pb_linear_combination_array<FieldT>(cm->bits.begin(), cm->bits.begin() , cm->bits.size()),
        h_packed,
        253 + 1,
        "pack pub key y into var"
    ));

    pk_x_packed.allocate(pb,2, "ZERO");

    unpacker_pk_x.reset(new multipacking_gadget<FieldT>(
        pb,
        pk_x, 
        pk_x_packed,
        253 + 1,
        "pack pub key y into var"
    ));

    pk_y_packed.allocate(pb,2, "ZERO");

    unpacker_pk_y.reset(new multipacking_gadget<FieldT>(
        pb,
        pk_y, 
        pk_y_packed,
        253 + 1,
        "pack pub key y into var"
    ));

    r_x_packed.allocate(pb,2, "ZERO");

    unpacker_r_x.reset(new multipacking_gadget<FieldT>(
        pb,
        r_x, 
        r_x_packed,
        253 + 1,
        "pack pub key y into var"
    ));

    r_y_packed.allocate(pb,2, "ZERO");
    unpacker_r_y.reset(new multipacking_gadget<FieldT>(
        pb,
        r_y, 
        r_y_packed,
        253 + 1,
        "pack pub key y into var"
    ));
  
    //take the first 253 bits of the hash
    h_bits.insert(h_bits.end(), h->bits.begin() , h->bits.end()); 
    jubjub_isOnCurve1.reset( new isOnCurve (pb, pk_x_packed[0], pk_y_packed[0], a, d, "Confirm public key is on the twiseted edwards curve"));
    jubjub_isOnCurve2.reset( new isOnCurve (pb, r_x_packed[0], r_y_packed[0], a, d, "Confirm r point is on the twiseted edwards curve"));

    jubjub_pointMultiplication_lhs.reset( new pointMultiplication (pb, a, d, b_x, b_y, S, lhs_x, lhs_y, " lhs check ", 256));
    jubjub_pointMultiplication_rhs.reset( new pointMultiplication (pb, a, d, pk_x_packed[0], pk_y_packed[0], h_bits, rhs_mul_x, rhs_mul_y, "rhs mul ", 253));
    jubjub_pointAddition.reset( new pointAddition (pb, a, d, rhs_mul_x[252], rhs_mul_y[252] , r_x_packed[0] , r_y_packed[0], rhs_x, rhs_y , "rhs addition"));
}



template<typename HashT>
void eddsa<HashT>::generate_r1cs_constraints()
{

    //constraint the inputs a,d , x_base, y_base
    //we make sure that the user passes the curve values
    this->pb.add_r1cs_constraint(ConstraintT({a} , {1}, {168700}),
                           FMT("a == 168700", "eddsa"));
    this->pb.add_r1cs_constraint(ConstraintT({d} , {1}, {168696}),
                           FMT("d == 168696", "eddsa"));

    this->pb.add_r1cs_constraint(ConstraintT({b_x} , {1}, {FieldT("17777552123799933955779906779655732241715742912184938656739573121738514868268")}),
                           FMT("d == 168696", "eddsa")); 

    this->pb.add_r1cs_constraint(ConstraintT({b_y} , {1}, {FieldT("2626589144620713026669568689430873010625803728049924121243784502389097019475")}),
                           FMT("d == 168696", "eddsa"));


    // not sure if we need to check pub key and r 
    // are on the curve. But doing it here for defense
    // in depth

    
    jubjub_isOnCurve1->generate_r1cs_constraints();
    jubjub_isOnCurve2->generate_r1cs_constraints();
      

    encode_point_r->generate_r1cs_constraints(true);
    encode_point_pk->generate_r1cs_constraints(true);
    encode_points->generate_r1cs_constraints(true);
    hint->generate_r1cs_constraints(true);


    unpacker_h->generate_r1cs_constraints(true);
    unpacker_pk_x->generate_r1cs_constraints(true);
    unpacker_pk_y->generate_r1cs_constraints(true);
    unpacker_r_x->generate_r1cs_constraints(true);
    unpacker_r_y->generate_r1cs_constraints(true);

    
    jubjub_pointMultiplication_lhs->generate_r1cs_constraints();
    jubjub_pointMultiplication_rhs->generate_r1cs_constraints();
    jubjub_pointAddition->generate_r1cs_constraints();


    this->pb.add_r1cs_constraint(ConstraintT({lhs_x[255]} , {1}, {rhs_x}),
                           FMT("lhs_x == rhs_x", "eddsa"));
    this->pb.add_r1cs_constraint(ConstraintT({lhs_y[255]} , {1}, {rhs_y}),
                           FMT("lhs_y == rhs_y", "eddsa")); 
    
}


template<typename HashT>
void eddsa<HashT>::generate_r1cs_witness()
{  
    encode_point_r->generate_r1cs_witness();
    encode_point_pk->generate_r1cs_witness();
    encode_points->generate_r1cs_witness();
    hint->generate_r1cs_witness();

    unpacker_pk_x->generate_r1cs_witness_from_bits();
    unpacker_pk_y->generate_r1cs_witness_from_bits();
    unpacker_r_x->generate_r1cs_witness_from_bits();
    unpacker_r_y->generate_r1cs_witness_from_bits();

    jubjub_isOnCurve1->generate_r1cs_witness();
    jubjub_isOnCurve2->generate_r1cs_witness();

    jubjub_pointMultiplication_lhs->generate_r1cs_witness(); 
    jubjub_pointMultiplication_rhs->generate_r1cs_witness();
    jubjub_pointAddition->generate_r1cs_witness();
 
    //std::cout << "h packed " << std::endl;
    unpacker_h->generate_r1cs_witness_from_bits();
 
     
    //debug
    /*
    std::cout << " h " << std::endl;
    for(uint i =0;i<256;i++) { 
        std::cout << this->pb.lc_val(h_bits[i]) << " ," ;
    }

    std::cout << " h packed " << this->pb.lc_val(h_packed[0]) << " " << this->pb.lc_val(h_packed[1]) << std::endl;
    std::cout << " pub_key_x packed " << this->pb.lc_val(pk_x_packed[0]) << " " << this->pb.lc_val(pk_x_packed[1]) << std::endl;
    std::cout << " pub_key_y packed " << this->pb.lc_val(pk_y_packed[0]) << " " << this->pb.lc_val(pk_y_packed[1]) << std::endl;
    std::cout << " r packed x" << this->pb.lc_val(r_x_packed[0]) << " " << this->pb.lc_val(pk_x_packed[1]) << std::endl;
    std::cout << " r packed y " << this->pb.lc_val(r_y_packed[0]) << " " << this->pb.lc_val(pk_y_packed[1]) << std::endl;
    */

//    std::cout << " pub_key_y " << this->pb.lc_val(pub_key_y[0]) << " " << this->pb.lc_val(pub_key_y[1]) << std::endl;

    //debug
    
    //std::cout <<  this->pb.lc_val(lhs_x[252]) << " " <<  this->pb.lc_val(rhs_x) << " "<< std::endl; // <<  this->pb.lc_val(S) << " " <<  this->pb.lc_val(H) ;
    /*

   std::cout << " message " << std::endl;
   for (uint i = 0 ; i < 256; i++) { 
        std::cout << this->pb.lc_val(message[i]) ; 
    }


    std::cout <<  this->pb.lc_val(pk_x_packed[0]) << " " << this->pb.lc_val(pk_y_packed[0]) << std::endl;
    std::cout <<  this->pb.lc_val(rhs_mul_x[253]) << " " << this->pb.lc_val(rhs_mul_y[253]) << std::endl;
    */
}


// namespace ethsnarks
}
