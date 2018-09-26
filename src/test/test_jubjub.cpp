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



#include "ethsnarks.hpp"

#include "jubjub/curve.hpp"
#include "jubjub/eddsa.hpp"
#include "jubjub/pedersen_commitment.hpp"
#include "gadgets/sha256_full.cpp"


namespace ethsnarks {


void tests()
{
    std::shared_ptr<isOnCurve> jubjub_isOnCurve;
    std::shared_ptr<pointAddition> jubjub_pointAddition;
    std::shared_ptr<isOnCurve> jubjub_isOnCurveX3Y3;

    ProtoboardT pb;

    VariableT x;
    VariableT y;

    VariableT x1;
    VariableT y1;
    VariableT x2;
    VariableT y2;
    VariableT x3;
    VariableT y3;

    VariableT x_zero;
    VariableT y_zero;


    VariableT a;
    VariableT d;

    x.allocate(pb, "x");
    y.allocate(pb, "y");

    x1.allocate(pb, "x1");
    y1.allocate(pb, "y1");
    x2.allocate(pb, "x2");
    y2.allocate(pb, "y2");
    x3.allocate(pb, "x3");
    y3.allocate(pb, "y3");


    x_zero.allocate(pb, "x_zero");
    y_zero.allocate(pb, "x_zero");


    a.allocate(pb, "a");
    d.allocate(pb, "d");

    pb.val(x) = FieldT("17777552123799933955779906779655732241715742912184938656739573121738514868268");
    pb.val(y) = FieldT("2626589144620713026669568689430873010625803728049924121243784502389097019475");
    pb.val(a) = FieldT("168700");
    pb.val(d) = FieldT("168696");

    pb.val(x1) = FieldT("17777552123799933955779906779655732241715742912184938656739573121738514868268");
    pb.val(y1) = FieldT("2626589144620713026669568689430873010625803728049924121243784502389097019475");
    pb.val(x2) = FieldT("17777552123799933955779906779655732241715742912184938656739573121738514868268");
    pb.val(y2) = FieldT("2626589144620713026669568689430873010625803728049924121243784502389097019475");


    pb.val(x_zero) = FieldT("0");
    pb.val(y_zero) = FieldT("1");



    jubjub_isOnCurve.reset( new isOnCurve (pb, x, y, a, d, "Confirm x, y is on the twiseted edwards curve"));
    jubjub_pointAddition.reset( new pointAddition (pb, a, d, x1, y1 , x2 , y2, x3, y3 , "x1, y1 + x2 , y2"));
    jubjub_isOnCurveX3Y3.reset( new isOnCurve (pb, x3, y3, a, d, "confirm x3, y3 is on the curve"));

    jubjub_isOnCurve->generate_r1cs_constraints();
    jubjub_pointAddition->generate_r1cs_constraints();
    jubjub_isOnCurveX3Y3->generate_r1cs_constraints();

    //check that the generator point is on the twisted edwards curve
    jubjub_isOnCurve->generate_r1cs_witness();
    jubjub_pointAddition->generate_r1cs_witness();
    jubjub_isOnCurveX3Y3->generate_r1cs_witness();



    //check the addition
    assert(FieldT("6890855772600357754907169075114257697580319025794532037257385534741338397365") == pb.lc_val(x3));
    assert(FieldT("4338620300185947561074059802482547481416142213883829469920100239455078257889") == pb.lc_val(y3));

    assert(pb.is_satisfied());

}


void test_pointAddition ()
{
    std::shared_ptr<pointAddition> jubjub_pointAddition;

    ProtoboardT pb;

    VariableT x;
    VariableT y;

    VariableT x1;
    VariableT y1;
    VariableT x2;
    VariableT y2;
    VariableT x3;
    VariableT y3;

    VariableT x_zero;
    VariableT y_zero;


    VariableT a;
    VariableT d;

    x.allocate(pb, "x");
    y.allocate(pb, "y");

    x1.allocate(pb, "x1");
    y1.allocate(pb, "y1");
    x2.allocate(pb, "x2");
    y2.allocate(pb, "y2");
    x3.allocate(pb, "x3");
    y3.allocate(pb, "y3");


    x_zero.allocate(pb, "x_zero");
    y_zero.allocate(pb, "x_zero");


    a.allocate(pb, "a");
    d.allocate(pb, "d");

    pb.val(x) = FieldT("17777552123799933955779906779655732241715742912184938656739573121738514868268");
    pb.val(y) = FieldT("2626589144620713026669568689430873010625803728049924121243784502389097019475");
    pb.val(a) = FieldT("168700");
    pb.val(d) = FieldT("168696");

    pb.val(x1) = FieldT("17777552123799933955779906779655732241715742912184938656739573121738514868268");
    pb.val(y1) = FieldT("2626589144620713026669568689430873010625803728049924121243784502389097019475");
    pb.val(x2) = FieldT("17777552123799933955779906779655732241715742912184938656739573121738514868268");
    pb.val(y2) = FieldT("2626589144620713026669568689430873010625803728049924121243784502389097019475");


    pb.val(x_zero) = FieldT("0");
    pb.val(y_zero) = FieldT("1");


    jubjub_pointAddition.reset( new pointAddition (pb, a, d, x1, y1 , x2 , y2, x3, y3 , "x1, y1 + x2 , y2"));
    jubjub_pointAddition->generate_r1cs_constraints();
    jubjub_pointAddition->generate_r1cs_witness();

    //check the addition
    assert(FieldT("6890855772600357754907169075114257697580319025794532037257385534741338397365") == pb.lc_val(x3));
    assert(FieldT("4338620300185947561074059802482547481416142213883829469920100239455078257889") == pb.lc_val(y3));

    // check the multiplication
    //assert(FieldT("0") == pb.lc_val(x_zero));
    //assert(FieldT("1") == pb.lc_val(y_zero));

    //std::cout << pb.lc_val(x_ret[1]) << " output " << pb.lc_val(y_ret[1]) << std::endl;

    //std::cout << "point addition " << pb.num_constraints() << " constraints" << std::endl;

    assert(pb.is_satisfied());
    //std::cout << pb.is_satisfied() << "\n";
}


void test_conditional_addition()
{ 
    std::shared_ptr<conditionalPointAddition> jubjub_conditionalPointAddition;
    std::shared_ptr<conditionalPointAddition> jubjub_conditionalPointAddition1;

    ProtoboardT pb;

    VariableT x;
    VariableT y;

    VariableT x_zero;
    VariableT y_zero;

    VariableT a;
    VariableT d;


    x.allocate(pb, "x");
    y.allocate(pb, "y");

    x_zero.allocate(pb, "x_zero");
    y_zero.allocate(pb, "x_zero");


    a.allocate(pb, "a");
    d.allocate(pb, "d");

    pb.val(x) = FieldT("17777552123799933955779906779655732241715742912184938656739573121738514868268");
    pb.val(y) = FieldT("2626589144620713026669568689430873010625803728049924121243784502389097019475");

    pb.val(a) = FieldT("168700");
    pb.val(d) = FieldT("168696");

    VariableArrayT coef;
    VariableArrayT x_ret;
    VariableArrayT y_ret;

    coef.allocate(pb, 253, FMT("annotation_prefix", " scaler to multiply by"));
    x_ret.allocate(pb, 253+1, FMT("annotation_prefix", " x res"));
    y_ret.allocate(pb, 253+1, FMT("annotation_prefix", " y res"));


    pb.val(coef[0]) = FieldT(1);
    pb.val(coef[1]) = FieldT(0);

    //this->add[0].reset( new conditionalPointAddition (this->pb, a, d, x_zero, y_zero , x_zero, y_zero, x_ret[1], y_ret[1], coef[0], "x1, y1 + x2 , y2"));

    jubjub_conditionalPointAddition.reset( new conditionalPointAddition (pb, a, d, x, y, x, y ,x_ret[0], y_ret[0],coef[0], " "));
    jubjub_conditionalPointAddition->generate_r1cs_constraints();
    jubjub_conditionalPointAddition->generate_r1cs_witness();



    jubjub_conditionalPointAddition.reset( new conditionalPointAddition (pb, a, d, x, y, x, y ,x_ret[1], y_ret[1],coef[1], " "));
    jubjub_conditionalPointAddition->generate_r1cs_constraints();
    jubjub_conditionalPointAddition->generate_r1cs_witness();

    //check the addition
    assert(FieldT("6890855772600357754907169075114257697580319025794532037257385534741338397365") == pb.lc_val(x_ret[0]));
    assert(FieldT("4338620300185947561074059802482547481416142213883829469920100239455078257889") == pb.lc_val(y_ret[0]));
    assert(FieldT("17777552123799933955779906779655732241715742912184938656739573121738514868268") == pb.lc_val(x_ret[1]));
    assert(FieldT("2626589144620713026669568689430873010625803728049924121243784502389097019475") == pb.lc_val(y_ret[1]));
    assert(pb.is_satisfied());


}


void test_pointMultiplication()
{
    std::shared_ptr<pointMultiplication> jubjub_pointMultiplication;
    ProtoboardT pb;

    VariableT x;
    VariableT y;

    VariableT a;
    VariableT d;


    x.allocate(pb, "x");
    y.allocate(pb, "y");

    a.allocate(pb, "a");
    d.allocate(pb, "d");

    pb.val(x) = FieldT("17777552123799933955779906779655732241715742912184938656739573121738514868268");
    pb.val(y) = FieldT("2626589144620713026669568689430873010625803728049924121243784502389097019475");

    pb.val(a) = FieldT("168700");
    pb.val(d) = FieldT("168696");

    VariableArrayT coef;


    VariableArrayT x_ret;
    VariableArrayT y_ret;



    x_ret.allocate(pb, 253, FMT("annotation_prefix", " x return"));
    y_ret.allocate(pb, 253, FMT("annotation_prefix", " y return"));

    coef.allocate(pb, 253, FMT("annotation_prefix", " scaler to multiply by"));

    coef.fill_with_bits(pb, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 , 1, 1, 1, 1});

    jubjub_pointMultiplication.reset( new pointMultiplication (pb, a, d, x, y, coef,x_ret, y_ret, " ", 253));
    jubjub_pointMultiplication->generate_r1cs_constraints();
    jubjub_pointMultiplication->generate_r1cs_witness();


    //debug
    /*
    for (uint i = 0 ; i < 255 ; i++) {
         std::cout << pb.lc_val(x_ret[i]) << " output " << pb.lc_val(y_ret[i]) << std::endl;
    }*/


    assert(FieldT("19372461775513343691590086534037741906533799473648040012278229434133483800898") == pb.lc_val(x_ret[249]));
    assert(FieldT("9458658722007214007257525444427903161243386465067105737478306991484593958249") == pb.lc_val(y_ret[249]));

    //check 7, 111 in bianry
    assert(FieldT("2323860911332798975737225840038489818948922802448566828157080989954871830560") == pb.lc_val(x_ret[250]));
    assert(FieldT("19716335860170617342854600407491621598417915846079864794713717598030286960291") == pb.lc_val(y_ret[250]));

    // check 15 , 1111 in binary 

    assert(FieldT("9407276749418864625568650125865534168179830182005426556252343362174020878457") == pb.lc_val(x_ret[251])); 
    assert(FieldT("6778521764145897584820260810756236306135110983984768137378792002317567424624") == pb.lc_val(y_ret[251]));

    // check 31 , 11111 in binary 

    assert(FieldT("7622845806798279333008973964667360626508482363013971390840869953521351129788") == pb.lc_val(x_ret[252]));
    assert(FieldT("120664075238337199387162984796177147820973068364675632137645760787230319545") == pb.lc_val(y_ret[252]));

    std::cout << pb.is_satisfied() << std::endl;
}


void test_pointMultiplication2()
{
    std::shared_ptr<pointMultiplication> jubjub_pointMultiplication;
    ProtoboardT pb;

    VariableT x;
    VariableT y;

    VariableT a;
    VariableT d;


    x.allocate(pb, "x");
    y.allocate(pb, "y");

    a.allocate(pb, "a");
    d.allocate(pb, "d");

    pb.val(x) = FieldT("17777552123799933955779906779655732241715742912184938656739573121738514868268");
    pb.val(y) = FieldT("2626589144620713026669568689430873010625803728049924121243784502389097019475");

    pb.val(a) = FieldT("168700");
    pb.val(d) = FieldT("168696");

    VariableArrayT coef;

    VariableArrayT x_ret;
    VariableArrayT y_ret;

    x_ret.allocate(pb, 253, FMT("annotation_prefix", " x return"));
    y_ret.allocate(pb, 253, FMT("annotation_prefix", " y return"));
    // todo convert to 253 -> 253
    coef.allocate(pb, 253, FMT("annotation_prefix", " scaler to multiply by"));


    coef.fill_with_bits(pb, {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1});

    jubjub_pointMultiplication.reset( new pointMultiplication (pb, a, d, x, y, coef,x_ret, y_ret, " ", 253));
    jubjub_pointMultiplication->generate_r1cs_constraints();
    jubjub_pointMultiplication->generate_r1cs_witness();

    assert(FieldT("14301684958125943009122272922675861319630543242194947245351673046543952469619") == pb.lc_val(x_ret[252]));
    assert(FieldT("11800725617493155580803527033124862356775833708153925911126323435989069641481") == pb.lc_val(y_ret[252]));
    std::cout << pb.is_satisfied() << std::endl;
    //std::cout << "point multiplicaion " << pb.num_constraints() <<  " constraints, " << pb.num_constraints() / 253 << " constarints per bit " << std::endl;
}

// test inputs taken from ../test/test_eddsa.py
template<typename HashT>
void test_eddsa()
{
    ProtoboardT pb;
    std::shared_ptr<eddsa<HashT>> jubjub_eddsa;

    VariableT base_x;
    VariableT base_y;

    VariableT a;
    VariableT d;
    //public key
    VariableT pub_x;
    VariableT pub_y;

    VariableT r_x;
    VariableT r_y;




    base_x.allocate(pb, "base x");
    base_y.allocate(pb, "base y");

    pub_x.allocate(pb, "pub_x");
    pub_y.allocate(pb, "pub_y");


    a.allocate(pb, "a");
    d.allocate(pb, "d");

    r_x.allocate(pb, "r_x");
    r_y.allocate(pb, "r_y");


    VariableArrayT S;
    VariableArrayT message;


    S.allocate(pb, 256, FMT("annotation_prefix", " scaler to multiply by"));
    message.allocate(pb, 256, FMT("annotation_prefix", " scaler to multiply by")); 



    pb.val(base_x) = FieldT("17777552123799933955779906779655732241715742912184938656739573121738514868268");
    pb.val(base_y) = FieldT("2626589144620713026669568689430873010625803728049924121243784502389097019475");

    pb.val(a) = FieldT("168700");
    pb.val(d) = FieldT("168696");

    VariableArrayT pk_x_bin;
    VariableArrayT pk_y_bin;
    VariableArrayT r_x_bin;
    VariableArrayT r_y_bin;



    pk_x_bin.allocate(pb, 256, FMT("annotation_prefix", " scaler to multiply by"));
    pk_y_bin.allocate(pb, 256, FMT("annotation_prefix", " scaler to multiply by"));
    r_x_bin.allocate(pb, 256, FMT("annotation_prefix", " scaler to multiply by"));
    r_y_bin.allocate(pb, 256, FMT("annotation_prefix", " scaler to multiply by"));

    S.fill_with_bits(pb,  { 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 0, 1, 1, 1, 0, 1 });
    message.fill_with_bits(pb,  { 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0 });
    pk_x_bin.fill_with_bits(pb,  { 0, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 0 });
    pk_y_bin.fill_with_bits(pb,  { 1, 1, 0, 1, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1, 0, 1, 1, 1, 0, 0, 1, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0 });
    r_x_bin.fill_with_bits(pb,  { 0, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 1, 0, 0, 1, 1, 1, 0, 0, 0 });
    r_y_bin.fill_with_bits(pb,  { 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0 });

/*

    S.fill_with_bits(pb,  { 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0 });

    message.fill_with_bits(pb,  { 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1 });
    pk_x_bin.fill_with_bits(pb,  { 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0 });
    pk_y_bin.fill_with_bits(pb,  { 1, 1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 0 });
    r_x_bin.fill_with_bits(pb,  { 1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0 });
    r_y_bin.fill_with_bits(pb,  { 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0 });
*/
    jubjub_eddsa.reset(new eddsa<HashT> (pb,a,d, pk_x_bin, pk_y_bin, base_x,base_y,r_x_bin, r_y_bin, message, S));
    jubjub_eddsa->generate_r1cs_constraints();
    jubjub_eddsa->generate_r1cs_witness();
    assert(pb.is_satisfied());
    std::cout << pb.is_satisfied() << std::endl;

}

// test inputs taken from ../test/test_pedersen.py
void test_pedersen()
{
    ProtoboardT pb;
    std::shared_ptr<pedersen_commitment> jubjub_pedersen_commitment;

    VariableT base_x;
    VariableT base_y;

    VariableT a;
    VariableT d;
    //public key
    VariableT h_x;
    VariableT h_y;

    VariableT commitment_x;
    VariableT commitment_y;


    base_x.allocate(pb, "base x");
    base_y.allocate(pb, "base y");

    h_x.allocate(pb, "h_x");
    h_y.allocate(pb, "h_y");


    a.allocate(pb, "a");
    d.allocate(pb, "d");

    commitment_x.allocate(pb, "r_x");
    commitment_y.allocate(pb, "r_y");


    pb.val(base_x) = FieldT("17777552123799933955779906779655732241715742912184938656739573121738514868268");
    pb.val(base_y) = FieldT("2626589144620713026669568689430873010625803728049924121243784502389097019475");

    pb.val(a) = FieldT("168700");
    pb.val(d) = FieldT("168696");

    pb.val(h_x) = FieldT("16540640123574156134436876038791482806971768689494387082833631921987005038935");
    pb.val(h_y) = FieldT("20819045374670962167435360035096875258406992893633759881276124905556507972311");


    pb.val(commitment_x) = FieldT("8010604480252997578874361183087746053332521656016812693508547791817401879458");
    pb.val(commitment_y) = FieldT("15523586168823793714775329447481371860621135473088351041443641753333446779329");


    VariableArrayT m;
    VariableArrayT r;

    m.allocate(pb, 253, FMT("annotation_prefix", " scaler to multiply by"));

    r.allocate(pb, 253, FMT("annotation_prefix", " scaler to multiply by"));
   
 
    m.fill_with_bits(pb,  {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 1});

    r.fill_with_bits(pb, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1});


    jubjub_pedersen_commitment.reset(new pedersen_commitment (pb,a,d, base_x, base_y, h_x, h_y,commitment_x, commitment_y,m, r));
    jubjub_pedersen_commitment->generate_r1cs_constraints();
    jubjub_pedersen_commitment->generate_r1cs_witness();
    assert(pb.is_satisfied());

}


// namespace ethsnarks
}

int main () {
    ethsnarks::ppT::init_public_params();

    ethsnarks::test_conditional_addition();
    ethsnarks::test_pointAddition();
    ethsnarks::test_pointMultiplication();
    ethsnarks::test_pointMultiplication2();

    typedef ethsnarks::sha256_full_gadget_512 HashT;
    ethsnarks::test_eddsa<HashT>();
    ethsnarks::test_pedersen();

    return 0;
}
