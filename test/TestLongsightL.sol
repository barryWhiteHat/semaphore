pragma solidity ^0.4.24;

import "truffle/Assert.sol";
import "../contracts/LongsightL.sol";


contract TestLongsightL
{
	function testKnownL12 () public
	{
		uint256[10] memory round_constants;
		LongsightL.ConstantsL12p5(round_constants);

		uint256 x = 3703141493535563179657531719960160174296085208671919316200479060314459804651;
		uint256 k = 134551314051432487569247388144051420116740427803855572138106146683954151557;
		uint256 expected = 9638538253242078011815100086590507856430665299520185056351852605094082194804;

		uint256 result = LongsightL.LongsightL12p5(x, k, round_constants);

		Assert.equal(result, expected, "Unexpected result");
	}
}
