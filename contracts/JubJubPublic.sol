pragma solidity ^0.4.24;

import "./JubJub.sol";

contract JubJubPublic
{
	function pointAdd(uint256[2] a, uint256[2] b)	
		public view returns (uint256[2])
	{
		return JubJub.pointAdd(a, b);
	}
}
