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

#include "longsightf_constants.cpp"

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
*                         C_i-1 |->(+)      |
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
*       output = x[ len(x) - 2 ]
*
*  Knowing the value of x2, x1 and C then x0 can be easily found, while
*  only knowing x0, C and the result finding x1 isn't as trivial.
*
* (%i1) solve([ x[2] = x[0] + (C+x[1])^5 ], [x[2]]);
*
*                 5         4       2  3       3  2      4      5
* (%o1)    [x  = C  + 5 x  C  + 10 x  C  + 10 x  C  + 5 x  C + x  + x ]
*            2           1          1          1         1      1    0
*
*/

template<typename FieldT>
class LongsightF_gadget : public gadget<FieldT>
{
public:
    const std::vector<FieldT> &round_constants;
    const pb_variable<FieldT> &start_L;
    const pb_variable<FieldT> &start_R;

    pb_variable_array<FieldT> round_squares;
    pb_variable_array<FieldT> rounds;

    LongsightF_gadget(
        protoboard<FieldT> &in_pb,
        const std::vector<FieldT> &in_constants,
        const pb_variable<FieldT> &in_x_L,
        const pb_variable<FieldT> &in_x_R,
        const std::string &in_annotation_prefix=""
    ) :
        gadget<FieldT>(in_pb, FMT(in_annotation_prefix, " LongsightF_gadget")),
        round_constants(in_constants),
        start_L(in_x_L),
        start_R(in_x_R),
        round_squares(),
        rounds()
    {
        round_squares.allocate(in_pb, round_constants.size() * 4, FMT(in_annotation_prefix, " round_squares"));

        rounds.allocate(in_pb, round_constants.size(), FMT(in_annotation_prefix, " rounds"));
    }

    const pb_variable<FieldT>& result() const
    {
        return rounds[ round_constants.size() - 1 ];
    }

    void generate_r1cs_constraints()
    {
        size_t j = 0;

        for( size_t i = 0; i < round_constants.size() - 2; i++ )
        {
            const pb_variable<FieldT>& xL = (
                i == 0 ? start_L
                       : rounds[i-1]);

            const pb_variable<FieldT>& xR = (
                i == 0 ? start_R
                       : (i == 1 ? start_L
                                 : rounds[i-2]));

            // -------------------------------------------------
            // Squares

                // (xL+C[i]) * (xL+C[i]) = j[1]
                this->pb.add_r1cs_constraint(
                    r1cs_constraint<FieldT>(
                        round_constants[i] + xL,
                        round_constants[i] + xL,
                        round_squares[j]));

                // j[1] * (xL+C[i]) = j[2]
                this->pb.add_r1cs_constraint(
                    r1cs_constraint<FieldT>(
                        round_squares[j],
                        round_constants[i] + xL,
                        round_squares[j+1]));

                // j[2] * (xL+C[i]) = j[3]
                this->pb.add_r1cs_constraint(
                    r1cs_constraint<FieldT>(
                        round_squares[j+1],
                        round_constants[i] + xL,
                        round_squares[j+2]));

                // j[3] * (xL+C[i]) = j[3]
                this->pb.add_r1cs_constraint(
                    r1cs_constraint<FieldT>(
                        round_squares[j+2],
                        round_constants[i] + xL,
                        round_squares[j+3]));

            // -------------------------------------------------
            // Intermediate outputs

                // ((j[(1+i)*4 + 3] + xR) * 1) = x[i]
                this->pb.add_r1cs_constraint(
                    r1cs_constraint<FieldT>(
                        1,
                        round_squares[j+3] + xR,
                        rounds[i]));

            // -------------------------------------------------
            // Move to next block of squares
            j += 4;
        }        
    }

    void generate_r1cs_witness()
    {
        size_t h = 0;
        for( size_t i = 0; i < round_constants.size(); i++ )
        {
            const FieldT& xR = (
                i == 0 ? this->pb.val(start_R)
                       : (i == 1 ? this->pb.val(start_L)
                                 : this->pb.val(rounds[i-2])));

            const FieldT& xL = (i == 0 ? this->pb.val(start_L) : this->pb.val(rounds[i-1]));

            // Intermediate squarings
            auto t = xL + round_constants[i];
            this->pb.val(round_squares[h]) = t * t;        // ^2  
            this->pb.val(round_squares[h+1]) = this->pb.val(round_squares[h]) * t;    // ^3
            this->pb.val(round_squares[h+2]) = this->pb.val(round_squares[h+1]) * t;    // ^4
            this->pb.val(round_squares[h+3]) = this->pb.val(round_squares[h+2]) * t;    // ^5

            // Then intermediate X point
            this->pb.val(rounds[i]) = xR + this->pb.val(round_squares[h+3]);

            // Next block of intermediate squarings
            h += 4;
        }
    }
};
