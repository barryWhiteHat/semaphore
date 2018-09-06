#ifndef LONGSIGHTL_HPP_
#define LONGSIGHTL_HPP_

#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>

#include "ethsnarks.hpp"
#include "longsightl_constants.hpp"

class LongsightL_round : public libsnark::gadget<ethsnarks::FieldT>
{
public:
    const libsnark::pb_variable<ethsnarks::FieldT> var_input_x;
    const libsnark::pb_variable<ethsnarks::FieldT> var_input_k;
    const ethsnarks::FieldT round_constant;

    const libsnark::pb_variable<ethsnarks::FieldT> var_sq2;      // n^2
    const libsnark::pb_variable<ethsnarks::FieldT> var_sq4;      // n^4
    const libsnark::pb_variable<ethsnarks::FieldT> var_sq5;      // n^5

    const libsnark::pb_variable<ethsnarks::FieldT> var_output;

    LongsightL_round(
        libsnark::protoboard<ethsnarks::FieldT> &in_pb,
        const libsnark::pb_variable<ethsnarks::FieldT> &in_x,
        const libsnark::pb_variable<ethsnarks::FieldT> &in_k,
        const ethsnarks::FieldT in_constant,
        const std::string &in_annotation_prefix=""
    );

    void generate_r1cs_constraints();

    void generate_r1cs_witness();

    const libsnark::pb_variable<ethsnarks::FieldT>& result() const;
};


class LongsightL_gadget : public libsnark::gadget<ethsnarks::FieldT>
{
public:
    std::vector<LongsightL_round> m_rounds;
    const std::vector<ethsnarks::FieldT> m_constants;

    const libsnark::pb_variable<ethsnarks::FieldT> start_x;

    LongsightL_gadget(
        libsnark::protoboard<ethsnarks::FieldT> &in_pb,
        const std::vector<ethsnarks::FieldT> in_constants,
        const libsnark::pb_variable<ethsnarks::FieldT> in_x,
        const libsnark::pb_variable<ethsnarks::FieldT> in_k,
        const std::string &in_annotation_prefix=""
    );

    const libsnark::pb_variable<ethsnarks::FieldT>& result() const;

    void generate_r1cs_constraints();

    void generate_r1cs_witness();
};



class LongsightL12p5_gadget : public LongsightL_gadget
{
public:
    LongsightL12p5_gadget(
        libsnark::protoboard<ethsnarks::FieldT> &in_pb,
        const libsnark::pb_variable<ethsnarks::FieldT> &in_x,
        const libsnark::pb_variable<ethsnarks::FieldT> &in_k,
        const std::string &in_annotation_prefix=""
    ) :
        LongsightL_gadget(in_pb, LongsightL12p5_constants_assign(), in_x, in_k, in_annotation_prefix)
    {
    }
};


#endif
