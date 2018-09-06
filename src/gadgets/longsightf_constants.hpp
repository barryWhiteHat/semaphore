#ifndef LONGSIGHTF_CONSTANTS_HPP_
#define LONGSIGHTF_CONSTANTS_HPP_

#include "ethsnarks.hpp"

void LongsightF12p5_constants_fill( std::vector<ethsnarks::FieldT> &round_constants );
const std::vector<ethsnarks::FieldT> LongsightF12p5_constants_assign( );

void LongsightF322p5_constants_fill( std::vector<ethsnarks::FieldT> &round_constants );
const std::vector<ethsnarks::FieldT> LongsightF322p5_constants_assign( );

// LONGSIGHTF_CONSTANTS_HPP_
#endif
