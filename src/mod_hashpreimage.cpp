// Copyright (c) 2018 HarryR
// License: LGPL-3.0+

#include "sha256/sha256_full_gadget.cpp"
#include "sha256/utils.cpp"


/**
* Verify that SHA256(left,right) == expected
*/
template<typename FieldT>
class mod_hashpreimage : public gadget<FieldT>
{
public:
    digest_variable<FieldT> output;
    sha256_full_gadget_512<FieldT> full_hasher;

    mod_hashpreimage(
        protoboard<FieldT> &in_pb,
        const digest_variable<FieldT> &in_left,
        const digest_variable<FieldT> &in_right,
        const std::string &annotation_prefix
    ) :
        gadget<FieldT>(in_pb, annotation_prefix),

        output(in_pb, SHA256_digest_size, FMT(annotation_prefix, " output")),

        full_hasher(in_pb, block_from_left_right<FieldT>(in_left, in_right), output, FMT(annotation_prefix, " full_hasher"))
    { }

    void generate_r1cs_constraints()
    {
        full_hasher.generate_r1cs_constraints(false);
        //hasher_final.generate_r1cs_constraints();
    }

    void generate_r1cs_witness(const libff::bit_vector &in_expected_bv)
    {
        full_hasher.generate_r1cs_witness();
        output.generate_r1cs_witness(in_expected_bv);
    }
};
