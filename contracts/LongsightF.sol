// Copyright (c) 2018 HarryR
// License: LGPL-3.0+

pragma solidity ^0.4.24;

library LongsightF
{
    // altBN curve order
    uint256 constant curve_order = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;

    function LongsightF_round( uint256 x_L, uint256 x_R, uint256 C )
        internal pure returns (uint256 out_x_L, uint256 out_x_R)
    {
        uint256 t;
        uint256 j;

        t = addmod(x_L, C, curve_order);
        j = mulmod(t, t, curve_order);  // t^2
        j = mulmod(j, j, curve_order);  // t^4
        j = mulmod(j, t, curve_order);  // t^5

        out_x_L = addmod(x_R, j, curve_order);
        out_x_R = x_L;
    }

    function LongsightF12p5( uint256 x_L, uint256 x_R, uint256[12] memory C )
        internal pure returns(uint256)
    {
        require( C.length == 12 );

        uint256 i;

        for( i = 0; i < 12; i++ )
        {
            (x_L, x_R) = LongsightF_round(x_L, x_R, C[i]);
        }

        return x_L;
    }

    function ConstantsF12p5( uint256[12] memory round_constants )
        internal pure
    {
        round_constants[0] = 9336620114827167869923498859127980590103364240696583408886253845392125160817;
        round_constants[1] = 3097701634898883580717426041390441804664600840868338920274917563720345204277;
        round_constants[2] = 6919612898038057791916645256413466826457988650789603174400580245024269484237;
        round_constants[3] = 12373248235398610018019354515575866139575957890599399735658359077613485745586;
        round_constants[4] = 12178720276748191834765270872874330302660717342306435169330425160608622414198;
        round_constants[5] = 12654473635035670897666833515211149425213079115687400922766102892038806696254;
        round_constants[6] = 5803527244780519758365893594472735003493250601443035435559501028975310374640;
        round_constants[7] = 18023926838810837144443709210922250402448392656984179386015092381424539088097;
        round_constants[8] = 15604988139282359442637099597056604525225514840814806598533644687247343409609;
        round_constants[9] = 9289165068034849533986824844919115303853088289329630653484526430810807199297;
        round_constants[10] = 9594698824678113512307522372073328072328276422950198814313564370933873503970;
        round_constants[11] = 6472602813823946000782534258725252462857406623127081287307236014094138287571;
    }
}