#include "ethsnarks.hpp"

namespace ethsnarks {

/**
* Depending on the address bit, output the correct left/right inputs
* for the merkle path authentication hash
*
* 0 = left
* 1 = right
*/
class merkle_path_selector : public GadgetT
{
public:
    const VariableT& m_input;
    const VariableT& m_pathvar;
    const VariableT& m_is_right;

    VariableT m_left_a;
    VariableT m_left_b;
    VariableT m_left;

    VariableT m_right_a;
    VariableT m_right_b;
    VariableT m_right;

    merkle_path_selector(
        ProtoboardT &in_pb,
        const VariableT &in_input,
        const VariableT &in_pathvar,
        const VariableT &in_is_right,
        const std::string in_annotation_prefix=""
    ) :
        GadgetT(in_pb, in_annotation_prefix),
        m_input(in_input),
        m_pathvar(in_pathvar),
        m_is_right(in_is_right)
    {
        m_left_a.allocate(in_pb, FMT(this->annotation_prefix, " left_a"));
        m_left_b.allocate(in_pb, FMT(this->annotation_prefix, " left_b"));
        m_left.allocate(in_pb, FMT(this->annotation_prefix, " left"));

        m_right_a.allocate(in_pb, FMT(this->annotation_prefix, " right_a"));
        m_right_b.allocate(in_pb, FMT(this->annotation_prefix, " right_b"));
        m_right.allocate(in_pb, FMT(this->annotation_prefix, " right"));
    }

    void generate_r1cs_constraints()
    {
        this->pb.add_r1cs_constraint(ConstraintT(1 - m_is_right, m_input, m_left_a));
        this->pb.add_r1cs_constraint(ConstraintT(m_is_right, m_pathvar, m_left_b));
        this->pb.add_r1cs_constraint(ConstraintT(1, m_left_a + m_left_b, m_left));

        this->pb.add_r1cs_constraint(ConstraintT(m_is_right, m_input, m_right_a));
        this->pb.add_r1cs_constraint(ConstraintT(1 - m_is_right, m_pathvar, m_right_b));
        this->pb.add_r1cs_constraint(ConstraintT(1, m_right_a + m_right_b, m_right));
    }

    void generate_r1cs_witness()
    {
        this->pb.val(m_left_a) = (FieldT::one() - this->pb.val(m_is_right)) * this->pb.val(m_input);
        this->pb.val(m_left_b) = this->pb.val(m_is_right) * this->pb.val(m_pathvar);
        this->pb.val(m_left) = this->pb.val(m_left_a) + this->pb.val(m_left_b);

        this->pb.val(m_right_a) = this->pb.val(m_is_right) * this->pb.val(m_input);
        this->pb.val(m_right_b) = (FieldT::one() - this->pb.val(m_is_right)) * this->pb.val(m_pathvar);
        this->pb.val(m_right) = this->pb.val(m_right_a) + this->pb.val(m_right_b);
    }

    const VariableT& left() const {
        return m_left;
    }

    const VariableT& right() const {
        return m_right;
    }
};


/**
* Merkle path authenticator
*/
template<typename HashT>
class merkle_path_authenticator : public GadgetT
{
private:
    const size_t m_depth;
    const VariableArrayT m_address_bits;
    const VariableT m_leaf;
    const VariableT m_expected_root;
    const VariableArrayT m_path;

    std::vector<merkle_path_selector> m_selectors;
    std::vector<HashT> m_hashers;

public:
    merkle_path_authenticator(
        ProtoboardT &in_pb,
        const size_t in_depth,
        const VariableArrayT &in_address_bits,
        const std::vector<FieldT> in_IVs,
        const VariableT &in_leaf,
        const VariableT &in_expected_root,
        const VariableArrayT &in_path,
        const std::string in_annotation_prefix = ""
    ) :
        GadgetT(in_pb, FMT(in_annotation_prefix, " merkle_path_authenticator")),
        m_depth(in_depth),
        m_address_bits(in_address_bits),
        m_leaf(in_leaf),
        m_expected_root(in_expected_root),
        m_path(in_path)
    {
        assert( in_IVs.size() == in_depth );
        assert( in_depth > 0 );

        for( size_t i = 0; i < m_depth; i++ )
        {
            if( i == 0 )
            {
                m_selectors.push_back(
                    merkle_path_selector(
                        in_pb, in_leaf, in_path[i], in_address_bits[i]));
            }
            else {
                m_selectors.push_back(
                    merkle_path_selector(
                        in_pb, m_hashers[i - 1].result(), in_path[i], in_address_bits[i]));
            }

            m_hashers.push_back(HashT(
                in_pb, in_IVs[i],
                {m_selectors[i].left(), m_selectors[i].right()},
                FMT(this->annotation_prefix, " hasher_%zu", i)));
        }
    }

    const VariableT& calculated_root() const
    {
        return m_hashers[ m_hashers.size() - 1 ];
    }

    bool is_valid() const
    {
        return this->pb.val(calculated_root()) == this->pb.val(m_expected_root);
    }

    void generate_r1cs_constraints()
    {
        size_t i;
        for( i = 0; i < m_hashers.size(); i++ )
        {
            m_selectors[i].generate_r1cs_constraints();
            m_hashers[i].generate_r1cs_constraints();
        }

        // Ensure root matches calculated path hash
        this->pb.add_r1cs_constraint(
            ConstraintT(1, m_hashers[i-1].result(), m_expected_root));
    }

    void generate_r1cs_witness()
    {
        size_t i;
        for( i = 0; i < m_hashers.size(); i++ )
        {
            m_selectors[i].generate_r1cs_witness();
            m_hashers[i].generate_r1cs_witness();
        }
    }
};

// ethsnarks
}
