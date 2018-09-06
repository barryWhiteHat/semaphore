// Copyright (c) 2018 HarryR
// License: LGPL-3.0+

#include <libsnark/gadgetlib1/gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>

using libsnark::gadget;
using libsnark::pb_variable;
using libsnark::pb_variable_array;
using libsnark::protoboard;
using libsnark::r1cs_constraint;
using libsnark::var_index_t;

#include "ethsnarks.hpp"
using ethsnarks::FieldT;

#include "longsightf_constants.hpp"

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


/* `allocate_var_index` is private, must use this workaround... */
static const var_index_t make_variable( protoboard<FieldT> &in_pb, const std::string &annotation="" )
{
    pb_variable<FieldT> x;
    x.allocate(in_pb, annotation);
    return x.index;
}


class LongsightL_round : public gadget<FieldT>
{
public:
    const pb_variable<FieldT> var_input_x;
    const pb_variable<FieldT> var_input_k;
    const FieldT round_constant;

    const pb_variable<FieldT> var_sq1;      // n^2
    const pb_variable<FieldT> var_sq2;      // n^4
    const pb_variable<FieldT> var_sq3;      // n^5

    const pb_variable<FieldT> var_output;

    LongsightL_round(
        protoboard<FieldT> &in_pb,
        const pb_variable<FieldT> &in_x,
        const pb_variable<FieldT> &in_k,
        const FieldT in_constant,
        const std::string &in_annotation_prefix=""
    ) :
        gadget<FieldT>(in_pb, FMT(in_annotation_prefix, " LongsightL_round")),
        var_input_x(in_x),
        var_input_k(in_k),
        round_constant(in_constant),

        var_sq1( make_variable(in_pb, FMT(in_annotation_prefix, " sq1")) ),
        var_sq2( make_variable(in_pb, FMT(in_annotation_prefix, " sq2")) ),
        var_sq3( make_variable(in_pb, FMT(in_annotation_prefix, " sq3")) )
    {

    }

    void generate_r1cs_constraints()
    {
        // ((x + k + C) * (x + k + C)) == sq1
        this->pb.add_r1cs_constraint(
                    r1cs_constraint<FieldT>(
                        var_input_x + var_input_k + round_constant,
                        var_input_x + var_input_k + round_constant,
                        var_sq1));

        // sq1 * sq1 == sq2
        this->pb.add_r1cs_constraint(
                    r1cs_constraint<FieldT>(
                        var_sq1,
                        var_sq1,
                        var_sq2));

        // sq2 * (x + k + C) == sq3
        this->pb.add_r1cs_constraint(
                    r1cs_constraint<FieldT>(
                        var_sq2,
                        var_input_x + var_input_k + round_constant,
                        var_sq3));

        // 1 * (sq3 + x) = out
        this->pb.add_r1cs_constraint(
                    r1cs_constraint<FieldT>(
                        1,
                        var_sq3 + var_input_x,
                        var_output));
    }

    void generate_r1cs_witness()
    {
        // t = x + k + C
        // sq1 = t * t
        // sq2 = sq1 * sq1
        // sq3 = sq2 * t
        // out = sq3 + x
        auto t = this->pb.val(var_input_x) + this->pb.val(var_input_k) + round_constant;
        this->pb.val(var_sq1) = t * t ;
        this->pb.val(var_sq2) = this->pb.val(var_sq1) * this->pb.val(var_sq1);
        this->pb.val(var_sq3) = this->pb.val(var_sq2) * t;
        this->pb.val(var_output) = this->pb.val(var_input_x) + this->pb.val(var_sq3);
    }

    const pb_variable<FieldT>& result() const {
        return var_output;
    }
};


class LongsightL_gadget : public gadget<FieldT>
{
public:
    std::vector<LongsightL_round> m_rounds;
    const std::vector<FieldT> m_constants;

    const pb_variable<FieldT> start_x;
    const pb_variable<FieldT> start_k;

    LongsightL_gadget(
        protoboard<FieldT> &in_pb,
        const std::vector<FieldT> in_constants,
        const pb_variable<FieldT> in_x,
        const pb_variable<FieldT> in_k,
        const std::string &in_annotation_prefix=""
    ) :
        gadget<FieldT>(in_pb, FMT(in_annotation_prefix, " LongsightL_gadget")),
        m_rounds(),
        m_constants(in_constants),
        start_x(in_x),
        start_k(in_k)
    {
        int i = 0;
        for( auto& round_constant : in_constants ) {
            if( i == 0 ) {
                // first round
                m_rounds.push_back(LongsightL_round(this->pb, start_x, start_k, round_constant,
                                                 FMT(in_annotation_prefix, "round-%d", i)));
            }
            else {
                // Every other round
                m_rounds.push_back(LongsightL_round(this->pb, m_rounds[m_rounds.size()].result(), start_k, round_constant,
                                                 FMT(in_annotation_prefix, "round-%d", i)));
            }
        }
    }

    const pb_variable<FieldT>& result() const
    {
        return m_rounds[ m_rounds.size() - 1 ].result();
    }

    void generate_r1cs_constraints()
    {
        for( size_t i = 0; i < m_rounds.size(); i++ )
        {
            m_rounds[i].generate_r1cs_constraints();
        }
    }

    void generate_r1cs_witness()
    {
        for( size_t i = 0; i < m_rounds.size(); i++ )
        {
            m_rounds[i].generate_r1cs_witness();
        }
    }
};


class LongsightL12p5_gadget : public LongsightL_gadget
{
public:
    LongsightL12p5_gadget(
        protoboard<FieldT> &in_pb,
        const pb_variable<FieldT> &in_x,
        const pb_variable<FieldT> &in_k,
        const std::string &in_annotation_prefix=""
    ) :
        LongsightL_gadget(in_pb, LongsightF12p5_constants_assign(), in_x, in_k, in_annotation_prefix)
    {        
    }
};
