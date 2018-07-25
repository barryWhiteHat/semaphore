pragma solidity ^0.4.24;

import "truffle/Assert.sol";
import "../contracts/SnarkUtils.sol";

contract TestSnarkUtils
{
	/**
	* Pack a single 256 bit word into two outputs
	*/
	function testPackWords256()
	{
		uint256[] memory input_words = new uint256[](1);
		uint256[] memory output_words = new uint256[](2);

		input_words[0] = 0xD294F6E585874FE640BE4CE636E6EF9E3ADC27620AA3221FDCF5C0A7C11C6F67;

		SnarkUtils.PackWords(input_words, output_words);

		Assert.equal(output_words[0], 3148911523101545054735209199478325155464765444384556179543606818372573931851, "Output word 0 mismatch");

		Assert.equal(output_words[1], 7, "Output word 1 mismatch");
	}
}