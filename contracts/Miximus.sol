/*    
    copyright 2018 to the Miximus Authors

    This file is part of Miximus.

    Miximus is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Miximus is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Miximus.  If not, see <https://www.gnu.org/licenses/>.
*/

pragma solidity ^0.4.24;

import "./Verifier.sol";

library Miximus
{
    struct Data {    
        bytes32 root;
        mapping (bytes32 => bool) nullifiers;
        Verifier zksnark_verify;
    }

    function isTrue (
        Data self,
        uint[2] a,
        uint[2] a_p,
        uint[2][2] b,
        uint[2] b_p,
        uint[2] c,
        uint[2] c_p,
        uint[2] h,
        uint[2] k,
        uint[] input)
        internal view returns (bool)
    {

        bytes32 _root = padZero(reverse(bytes32(input[0])));
        require(_root == padZero(self.root));

        //require( self.nulifiers[x] == false );

        //require(self.zksnark_verify.verifyTx(a,a_p,b,b_p,c,c_p,h,k,input));      
        return(true);
    }

    function padZero(bytes32 x)
        internal pure returns(bytes32)
    {
                 //0x1111111111111111111111113fdc3192693e28ff6aee95320075e4c26be03308
        return(x & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0);
    }

    function reverseByte(uint a) public pure returns (uint) {
        uint c = 0xf070b030d0509010e060a020c0408000;

        return (( c >> ((a & 0xF)*8)) & 0xF0)   +
               (( c >> (((a >> 4)&0xF)*8) + 4) & 0xF);
    }

    //flip endinaness
    function reverse(bytes32 a)
        internal pure returns(bytes32)
    {
        uint r;
        uint i;
        uint b;
        for (i=0; i<32; i++) {
            b = (uint(a) >> ((31-i)*8)) & 0xff;
            b = reverseByte(b);
            r += b << (i*8);
        }
        return bytes32(r);
    }
}
