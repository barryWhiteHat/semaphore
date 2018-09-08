#ifndef ETHSNARKS_ONEWAYFUNCTION_HPP_
#define ETHSNARKS_ONEWAYFUNCTION_HPP_

#include "ethsnarks.hpp"

#include <libsnark/gadgetlib1/gadget.hpp>

template<class CipherT, typename MessageT>
class MiyaguchiPreneel_OWF : libsnark::gadget<ethsnarks::FieldT>
{
public:
	std::vector<CipherT> m_ciphers;
	libsnark::pb_variable_array<ethsnarks::FieldT> m_outputs;
	std::vector<MessageT> m_messages;

	MiyaguchiPreneel_OWF(
		libsnark::protoboard<ethsnarks::FieldT> &in_pb,
		MessageT &in_IV,
		std::vector<MessageT> &in_messages,
		const std::string &in_annotation_prefix=""
	) :
		gadget(in_pb, in_annotation_prefix),
		m_messages(in_messages)
	{
		m_outputs.allocate(in_pb, in_messages.size());

		int i = 0;		
		for( auto& m_i : in_messages ) {
			if( i == 0 ) {
				m_ciphers.push_back( CipherT(in_pb, m_i, in_IV, FMT(in_annotation_prefix, " Cipher_%d", i)) );
			}
			else {
				m_ciphers.push_back( CipherT(in_pb, m_i, m_outputs[i - 1], FMT(in_annotation_prefix, " Cipher_%d", i)) );
			}
			i += 1;
		}
	}

	MessageT result() const {
		return m_outputs[ m_outputs.size() - 1 ];
	}

	void generate_r1cs_constraints ()
	{
		size_t i;
		for( i = 0; i < m_ciphers.size(); i++ )
		{
			m_ciphers[i++].generate_r1cs_constraints();

			if( i == 0 ) {
				this->pb.add_r1cs_constraint(
					libsnark::r1cs_constraint<ethsnarks::FieldT>(
						1,
						m_ciphers[i].result() + m_messages[i],
						m_outputs[i]
						));
			}
			else {
				this->pb.add_r1cs_constraint(
					libsnark::r1cs_constraint<ethsnarks::FieldT>(
						1,
						m_outputs[i-1] + m_ciphers[i].result() + m_messages[i],
						m_outputs[i]
						));
			}
		}
	}

	void generate_r1cs_witness ()
	{
		size_t i;
		for( i = 0; i < m_ciphers.size(); i++ )
		{
			m_ciphers[i].generate_r1cs_witness();

			if( i == 0 ) {
				this->pb.val( m_outputs[i] ) = pb.val(m_ciphers[i].result()) + pb.val(m_messages[i]);
			}
			else {
				// H_{i-1} + m_i + k_i
				this->pb.val( m_outputs[i] ) = pb.val(m_outputs[i - 1]) + pb.val(m_ciphers[i].result()) + pb.val(m_messages[i]);
			}
		}
	}
};

// ETHSNARKS_ONEWAYFUNCTION_HPP_
#endif
