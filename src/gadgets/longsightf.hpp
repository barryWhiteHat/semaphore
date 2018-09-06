#ifndef LONGSIGHTF_HPP_
#define LONGSIGHTF_HPP_

#include "ethsnarks.hpp"
#include "longsightf_constants.hpp"

#include <libsnark/gadgetlib1/gadget.hpp>

class LongsightF_gadget : public libsnark::gadget<ethsnarks::FieldT>
{
public:
    const std::vector<ethsnarks::FieldT> round_constants;
    const libsnark::pb_variable<ethsnarks::FieldT> start_L;
    const libsnark::pb_variable<ethsnarks::FieldT> start_R;

    libsnark::pb_variable_array<ethsnarks::FieldT> round_squares;
    libsnark::pb_variable_array<ethsnarks::FieldT> rounds;

    LongsightF_gadget(
        libsnark::protoboard<ethsnarks::FieldT> &in_pb,
        const std::vector<ethsnarks::FieldT> in_constants,
        const libsnark::pb_variable<ethsnarks::FieldT> in_x_L,
        const libsnark::pb_variable<ethsnarks::FieldT> in_x_R,
        const std::string &in_annotation_prefix="",
        const bool do_allocate=true
    );

    void allocate();

    const libsnark::pb_variable<ethsnarks::FieldT>& result() const;

    void generate_r1cs_constraints();

    void generate_r1cs_witness();
};

class LongsightF12p5_gadget : public LongsightF_gadget
{
public:
    LongsightF12p5_gadget(
        libsnark::protoboard<ethsnarks::FieldT> &in_pb,
        const libsnark::pb_variable<ethsnarks::FieldT> &in_x_L,
        const libsnark::pb_variable<ethsnarks::FieldT> &in_x_R,
        const std::string &in_annotation_prefix=""
    ) :
        LongsightF_gadget(in_pb, LongsightF12p5_constants_assign(), in_x_L, in_x_R, in_annotation_prefix, false)
    {        
		this->allocate();
    }
};


class LongsightF322p5_gadget : public LongsightF_gadget
{
public:
    LongsightF322p5_gadget(
        libsnark::protoboard<ethsnarks::FieldT> &in_pb,
        const libsnark::pb_variable<ethsnarks::FieldT> &in_x_L,
        const libsnark::pb_variable<ethsnarks::FieldT> &in_x_R,
        const std::string &in_annotation_prefix=""
    ) :
        LongsightF_gadget(in_pb, LongsightF322p5_constants_assign(), in_x_L, in_x_R, in_annotation_prefix, false)
    {
        this->allocate();
    }
};


#endif
