pragma solidity ^0.4.24;

import "truffle/Assert.sol";
import "../contracts/LongsightF.sol";


contract TestLongsightF
{
	function testKnown () public
	{
		uint256[12] memory round_constants;
		LongsightF.ConstantsF12p5(round_constants);

		uint256 x_L = 3703141493535563179657531719960160174296085208671919316200479060314459804651;
		uint256 x_R = 134551314051432487569247388144051420116740427803855572138106146683954151557;
		uint256 expected = 14698330907891059605542875061480191518388361330761392167383706051673460062628;

		uint256 result = LongsightF.LongsightF12p5(x_L, x_R, round_constants);

		Assert.equal(result, expected, "Unexpected result");
	}
}
