// Copyright (c) 2018 HarryR
// License: LGPL-3.0+

#pragma once

#include <libsnark/gadgetlib1/gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>

using libsnark::gadget;
using libsnark::pb_variable;
using libsnark::pb_variable_array;
using libsnark::protoboard;
using libsnark::r1cs_constraint;

/**
* The LongsightF function can be represented as a circuit:
*
*         L       R
*        x_1     x_0
*         _       _
*         |       |
*         |--------------------.
*         |       |            |
*         v       |            |
* C_0 |->(+)      |            |    j[i] = x[i+1] + C[i]
*         |       |            |
*         v       |            | 
*       (^5)      |            |    k[i] = j[i]^5
*         |       v            |
*          `---->(+) = x_2     |  x[i+2] = x[i] + k[i]
*                      _       |
*                      |       |
*                      |--------------------.
*                      |       |            |
*                      v       |            |
*              C_i |->(+)      |            |
*                      |       |            |
*                      v       |            |
*                    (^5)      |            |
*                      |       v            |
*                      `----->(+) = x_(i+2) |
*                                   _       |
*                                   |       |
*                                   v       |
*                       C_(n-1) |->(+)      |
*                                   |       |
*                                   v       |
*                                  (^5)     |
*                                   |       v
*                                   `----->(+) = output
*
*  The round function can be expressed as:
*
*       x[i+2] = x[i] + (x[i+1] + C[i])^5
*
*  Where x[] must start with at least 2 values
*
*  If the values x[0] and x[1] are the variables L and R
*  and x[] is going to be the intermediate state of the function
*  then the first two rounds must substitute those variables, e.g.
*
*       x[0] = R      + (L      + C[i])^5          when i = 0
*       x[1] = L      + (x[i-1] + C[i])^5          when i = 1
*       x[i] = x[i-2] + (x[i-1] + C[i])^5          when i > 1
*
*       output = x[ len(x) - 1]
*
*  We can solve x0 and x1, knowing the result and C, e.g. in Maxima:
*
* (%i1) solve([ x[2] = x[0] + (C+x[1])^5 ], [x[2]]);
*
*                 5         4       2  3       3  2      4      5
* (%o1)    [x  = C  + 5 x  C  + 10 x  C  + 10 x  C  + 5 x  C + x  + x ]
*            2           1          1          1         1      1    0
*
*  Knowing the value of x2, x1 and C then x0 can be calculated, while
*  only knowing x0 and C the calculation isn't as trivial.
*/


template<typename FieldT>
class LongsightF_gadget : public gadget<FieldT>
{
public:
    const std::vector<FieldT> &round_constants,
    const pb_variable<FieldT> &start_L;
    const pb_variable<FieldT> &start_R;

    pb_variable_array<FieldT> intermediate_j;
    pb_variable_array<FieldT> intermediate_x;

    LongsightF_gadget(
        protoboard<FieldT> &in_pb,
        const std::vector<FieldT> &in_constants,
        const pb_variable<FieldT> &in_x_L;
        const pb_variable<FieldT> &in_x_R;
        const std::string &in_annotation_prefix=""
    ) :
        gadget<FieldT>(in_pb, FMT(in_annotation_prefix, " LongsightF_gadget")),
        round_constants(in_constants),
        start_L(in_x_L),
        start_R(in_x_R),
        intermediate_j(),
        intermediate_x(),
    {
        intermediate_j.allocate(pb, round_constants.size(), FMT(annotation_prefix, " intermediate_j"));

        intermediate_x.allocate(pb, round_constants.size(), FMT(annotation_prefix, " intermediate_x"));
    }

    const pb_variable<FieldT>& result()
    {
        return intermediate_x[ round_constants.size() - 1 ];
    }

    void generate_r1cs_constraints()
    {
        // In the form of: (A * B) - C = 0
        // x[i+1] * x[i+1] - j[1] = 0   # x[i+1]^2
        // j[1]   * j[0]   - j[2] = 0   # x[i+1]^3
        // j[2]   * j[0]   - j[3] = 0   # x[i+1]^4
        // j[3]   * j[0]   - j[4] = 0   # x[i+1]^5
        // ((j[i*4] + x[i]) * 1) - x[i+2] = 0
    }

    void generate_r1cs_witness()
    {
        for( size_t i = 0; i < round_constants.size(); i++ )
        {
            FieldT& j;
            FieldT& k;

            if( i == 0 ) {
                j = pb.val(start_R);
                k = pb.val(start_L);
            }
            else if( i == 1 ) {
                j = pb.val(start_L);
                k = pb.val(intermediate_x[i-1]);
            }
            else {
                j = pb.val(intermediate_x[i-2]);
                k = pb.val(intermediate_x[i-1]);
            }

            pb.val(intermediate_x[i]) = j + (k + pb.val(round_constants[i]))^5;
        }
    }
};