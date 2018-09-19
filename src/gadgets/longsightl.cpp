// Copyright (c) 2018 HarryR
// License: LGPL-3.0+

#include "ethsnarks.hpp"
#include "utils.hpp"
#include "longsightl.hpp"

/**
* First round
*
*       x         k
*       |         |
*       |         |
*       |---(+)---|     X[0] = x + k
*       |    |    |
*       |  (n^5)  |     Y[0] = X[0]^5
*       |    |    |
*        `--(+)   |     Z[0] = Y[0] + x 
*            |    |
*            |    |
******************************************
* Second round
*            |    |
*  ,---------|    |
*  |         |    |
*  |        (+)---|     X[1] = Z[0] + k  
*  |         |    |
*  | C[0] --(+)   |     Y[1] = X[1] + C[0]
*  |         |    |
*  |       (n^5)  |     W[1] = Y[1]^5
*  |         |    |
*  `--------(+)   |     Z[1] = Z[0] + Y[1]
*            |    |
******************************************
* i'th round
*            |    |
*  ,---------|    |
*  |         |    |
*  |        (+)---|     X[i] = Z[i-1] + k  
*  |         |    |
*  | C[i] --(+)   |     Y[i] = X[i] + C[i]
*  |         |    |
*  |       (n^5)  |     W[i] = Y[i]^5
*  |         |    |
*  `--------(+)   |     Z[i] = Z[i-1] + Y[i]
*            |    |
******************************************
* Last round
*            |    |
*       ,----|    |
*       |    |    |
*       |   (+)---'     X[i] = X[i-1] + k
*       |    |     
*       |  (n^5)        Y[i] = X[i]^5
*       |    |     
*        `--(+)         Z[i] = Z[i-1] + Y[i] 
*            |    
*            |
*          result
*/


namespace ethsnarks {



LongsightL_round::LongsightL_round(
    ProtoboardT &in_pb,
    const VariableT &in_x,
    const VariableT &in_k,
    const FieldT in_constant,
    const std::string &in_annotation_prefix
) :
    GadgetT(in_pb, FMT(in_annotation_prefix, " LongsightL_round")),
    var_input_x(in_x),
    var_input_k(in_k),
    round_constant(in_constant)
{
    var_sq2.allocate(in_pb, FMT(this->annotation_prefix, ".sq2"));
    var_sq4.allocate(in_pb, FMT(this->annotation_prefix, ".sq4"));
    var_sq5.allocate(in_pb, FMT(this->annotation_prefix, ".sq5"));
    var_output.allocate(in_pb, FMT(this->annotation_prefix, ".out"));
}


void LongsightL_round::generate_r1cs_constraints()
{
    // t = x + k + C_i
    auto t = var_input_x + var_input_k + round_constant;

    // sq2 == t * t == t^2
    this->pb.add_r1cs_constraint(
                ConstraintT(
                    t,
                    t,
                    var_sq2), "t*t=sq2");

    // sq2 * sq2 == sq4 == t^4
    this->pb.add_r1cs_constraint(
                ConstraintT(
                    var_sq2,
                    var_sq2,
                    var_sq4), "sq2*sq2=sq4");

    // sq4 * t == sq5 == t^5
    this->pb.add_r1cs_constraint(
                ConstraintT(
                    var_sq4,
                    t,
                    var_sq5), "sq4*t=sq5");

    // 1 * (sq5 + x) = out
    this->pb.add_r1cs_constraint(
                ConstraintT(
                    1,
                    var_sq5 + var_input_x,
                    var_output), "sq5+x=out");
}


void LongsightL_round::generate_r1cs_witness()
{
    // t = x + k + C
    auto t = this->pb.val(var_input_x) + this->pb.val(var_input_k) + round_constant;

    // sq2 = t * t   (t^2)
    this->pb.val(var_sq2) = t * t ;

    // sq4 = sq2 * sq2  (t^4)
    this->pb.val(var_sq4) = this->pb.val(var_sq2) * this->pb.val(var_sq2);

    // sq5 = sq2 * t    (t^5)
    this->pb.val(var_sq5) = this->pb.val(var_sq4) * t;

    // out = sq5 + x
    this->pb.val(var_output) = this->pb.val(var_input_x) + this->pb.val(var_sq5);
}


const VariableT& LongsightL_round::result() const {
    return var_output;
}


LongsightL_gadget::LongsightL_gadget(
    ProtoboardT &in_pb,
    const std::vector<FieldT> &in_constants,
    const VariableT in_x,
    const VariableT in_k,
    const std::string &in_annotation_prefix
) :
    GadgetT(in_pb, FMT(in_annotation_prefix, " LongsightL_gadget")),
    m_rounds(),
    m_constants(in_constants),
    start_x(in_x)
{
    int i = 0;
    for( auto& round_constant : in_constants ) {
        if( i++ == 0 ) {
            // first round
            m_rounds.push_back(LongsightL_round(this->pb, start_x, in_k, round_constant,
                                             FMT(in_annotation_prefix, "round-%d", i)));
        }
        else {
            // Every other round
            m_rounds.push_back(LongsightL_round(this->pb, m_rounds[m_rounds.size() - 1].result(), in_k, round_constant,
                                             FMT(in_annotation_prefix, "round-%d", i)));
        }
    }
}


const VariableT& LongsightL_gadget::result() const
{
    return m_rounds[ m_rounds.size() - 1 ].result();
}


void LongsightL_gadget::generate_r1cs_constraints()
{
    for( size_t i = 0; i < m_rounds.size(); i++ )
    {
        m_rounds[i].generate_r1cs_constraints();
    }
}


void LongsightL_gadget::generate_r1cs_witness()
{
    for( size_t i = 0; i < m_rounds.size(); i++ )
    {
        m_rounds[i].generate_r1cs_witness();
    }
}

// ethsnarks
}
