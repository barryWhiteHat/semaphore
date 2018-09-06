// Copyright (c) 2018 HarryR
// License: LGPL-3.0+

pragma solidity ^0.4.24;

library LongsightL
{
    // altBN curve order
    uint256 constant curve_order = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;


    /**
    * x + (x + k + c)^5
    */
    function LongsightL_round( uint256 in_x, uint256 in_k, uint256 in_C )
        internal pure returns (uint256 out_x)
    {
        uint256 t;
        uint256 j;

        t = addmod(in_x, in_C, curve_order);
        t = addmod(t, in_k, curve_order);
        j = mulmod(t, t, curve_order);  // t^2
        j = mulmod(j, j, curve_order);  // t^4
        j = mulmod(j, t, curve_order);  // t^5

        out_x = addmod(in_x, j, curve_order);
    }


    /**
    * According to MiMC paper, first and last round constants must be zero, so for 12 rounds, require 10 constants
    */
    function LongsightL12p5( uint256 in_x, uint256 in_k, uint256[10] memory C )
        internal pure returns(uint256)
    {
        require( C.length == 10 );

        uint256 i;

        in_x = LongsightL_round(in_x, in_k, 0);

        for( i = 0; i < 10; i++ )
        {
            in_x = LongsightL_round(in_x, in_k, C[i]);
        }

        in_x = LongsightL_round(in_x, in_k, 0);

        return in_x;
    }


    function LongsightL12p5_MP( uint256[2] memory in_M, uint256 in_IV, uint256[10] memory C )
        internal pure returns (uint256 H_i)
    {
        uint256 i;
        uint256 k_i = in_IV;
        H_i = 0;

        for( i = 0; i < in_M.length; i++ ) {
            k_i = LongsightL12p5(in_M[i], k_i, C);
            H_i = addmod(H_i, in_M[i], curve_order);
            H_i = addmod(H_i, k_i, curve_order);
        }
    }


    function ConstantsL12p5( uint256[10] memory round_constants )
        internal pure
    {
        round_constants[0] = 1123290141928164279008888891766378473818224497744673926276953901234820430642;
        round_constants[1] = 10985366949788476814992264851760069583580863264413713065688271499338204201663;
        round_constants[2] = 697060791212164642694445403044920191448639837622426114750683064775524708091;
        round_constants[3] = 2927275006259720461621994090854281014055545305739622272831795049357503845045;
        round_constants[4] = 10412319102912193718627660805338892121530111706856302539498702298083887810988;
        round_constants[5] = 620349011339579072558087154478991228793293385614105914560448303472115289790;
        round_constants[6] = 10511143232444605554382744833253216315052468071414858166502934581708567653712;
        round_constants[7] = 14812403264587974755203859916430999098674340519454779971315944472173228373660;
        round_constants[8] = 11084405208266551212633630110871834096841516447067573520449405021724864800341;
        round_constants[9] = 5309209836577867454067352188316145237209274990329546025817814580523329585168;
    }
}
