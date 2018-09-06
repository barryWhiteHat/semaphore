#ifndef LONGSIGHTL_HPP_
#define LONGSIGHTL_HPP_

class LongsightL_round : public gadget<ethsnarks::FieldT>
{
public:
    const pb_variable<ethsnarks::FieldT> var_input_x;
    const pb_variable<ethsnarks::FieldT> var_input_k;
    const FieldT round_constant;

    const pb_variable<ethsnarks::FieldT> var_sq1;      // n^2
    const pb_variable<ethsnarks::FieldT> var_sq2;      // n^4
    const pb_variable<ethsnarks::FieldT> var_sq3;      // n^5

    const pb_variable<ethsnarks::FieldT> var_output;

    LongsightL_round(
        protoboard<ethsnarks::FieldT> &in_pb,
        const pb_variable<ethsnarks::FieldT> &in_x,
        const pb_variable<ethsnarks::FieldT> &in_k,
        const FieldT in_constant,
        const std::string &in_annotation_prefix=""
    );

    void generate_r1cs_constraints();

    void generate_r1cs_witness();

    const pb_variable<ethsnarks::FieldT>& result() const;
};

#endif
