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
pragma experimental ABIEncoderV2;

import "./Verifier.sol";
import "./SnarkUtils.sol";
import "./MerkleTree.sol";


contract Miximus
{
    using MerkleTree for MerkleTree.Data;

    uint constant AMOUNT = 1 ether;

    mapping (uint256 => bool) nullifiers;

    MerkleTree.Data tree;

    function GetVerifyingKey ()
        internal pure returns (Verifier.VerifyingKey memory);

    function Deposit(uint256 leaf)
        public payable returns (uint256)
    {
        require( msg.value == AMOUNT );

        return tree.Insert(leaf);
    }


    function Withdraw(
        uint256 in_root,
        uint256 in_nullifier,
        Verifier.Proof in_proof
    )
        public
    {
        require( false == nullifiers[in_nullifier] );

        uint256[] memory snark_input = new uint256[](3);

        snark_input[0] = SnarkUtils.ReverseBits(in_root);

        snark_input[1] = SnarkUtils.ReverseBits(in_nullifier);

        snark_input[2] = SnarkUtils.ReverseBits(uint256(sha256(
            abi.encodePacked(
                address(this),
                msg.sender
            )))) % Verifier.ScalarField();

        Verifier.VerifyingKey memory vk = GetVerifyingKey();

        bool is_valid = Verifier.Verify( vk, in_proof, snark_input );

        require( is_valid );

        nullifiers[in_nullifier] = true;

        msg.sender.transfer(AMOUNT);
    }
}
