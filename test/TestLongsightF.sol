pragma solidity ^0.4.24;

import "truffle/Assert.sol";
import "../contracts/LongsightF.sol";


contract TestLongsightF
{
	function testKnown () public
	{
		uint256[152] memory round_constants;
		LongsightF.ConstantsF152p5(round_constants);

		uint256 x_L = 21871881226116355513319084168586976250335411806112527735069209751513595455673;
		uint256 x_R = 55049861378429053168722197095693172831329974911537953231866155060049976290;
		uint256 expected = 11801552584949094581972187388927133931539817817986253233814495442311083852545;

		uint256 result = LongsightF.LongsightF152p5(x_L, x_R, round_constants);

		Assert.equal(result, expected, "Unexpected result");
	}
}
