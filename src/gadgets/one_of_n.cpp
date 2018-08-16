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
using libsnark::generate_boolean_r1cs_constraint;


template<typename FieldT>
class one_of_n : public gadget<FieldT>
{
public:
    protoboard<FieldT> &pb;

    const pb_variable<FieldT> &our_item;
    const pb_variable_array<FieldT> &items;
    pb_variable_array<FieldT> toggles;
    pb_variable_array<FieldT> toggles_sum;
    const std::string annotation_prefix="";

    one_of_n(
        protoboard<FieldT> &in_pb,
        const pb_variable<FieldT> &in_our_item,
        const pb_variable_array<FieldT> &in_items,
        const std::string &in_annotation_prefix=""
    ) :
        gadget<FieldT>(in_pb, FMT(in_annotation_prefix, " one_of_n")),
        pb(in_pb),
        our_item(in_our_item),
        items(in_items),
        toggles(),
        toggles_sum(),
        annotation_prefix(in_annotation_prefix)
    {
        assert( in_items.size() > 0 );

        toggles.allocate(pb, in_items.size(), FMT(annotation_prefix, " toggles"));

        toggles_sum.allocate(pb, in_items.size(), FMT(annotation_prefix, " toggles_sum"));
    }

    void generate_r1cs_constraints()
    {
        // ensure bitness of toggles
        for( size_t i = 0; i < items.size(); i++ )
        {
            generate_boolean_r1cs_constraint<FieldT>(pb, toggles[i], FMT(annotation_prefix, " toggles_%zu", i));
        }

        // ensure the sum of toggles equals 1
        for( size_t i = 1; i < toggles.size(); i++ )
        {
            pb.add_r1cs_constraint(
                r1cs_constraint<FieldT>(
                    toggles_sum[i-1] + toggles[i],
                    FieldT::one(),
                    toggles_sum[i]));
        }
        pb.add_r1cs_constraint(
                r1cs_constraint<FieldT>(
                    toggles_sum[items.size()-1],
                    FieldT::one(),
                    FieldT::one()));

        // XXX: why use `lc_val` here?
        auto our_item_lc_val = pb.lc_val(our_item);

        // then multiply toggles with items
        // subtract toggle*our_item
        for( size_t i = 0; i < items.size(); i++ )
        {
            pb.add_r1cs_constraint(
                r1cs_constraint<FieldT>(
                    items[i],
                    toggles[i],
                    toggles[i] * our_item_lc_val));
        }
    }

    void generate_r1cs_witness()
    {
        for( size_t i = 0; i < toggles.size(); i++ )
        {
            if( pb.val(items[i]) == pb.val(our_item) )
            {
                pb.val(toggles[i]) = FieldT::one();
                break;
            }
        }

        // create toggle sum
        toggles_sum[0] = toggles[0];
        for( size_t i = 1; i < toggles.size(); i++ )
        {
            pb.val(toggles_sum[i]) = pb.val(toggles_sum[i-1]) + pb.val(toggles[i]);
        }
    }
};
