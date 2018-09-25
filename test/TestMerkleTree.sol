pragma solidity ^0.4.24;

import "truffle/Assert.sol";
import "../contracts/MerkleTree.sol";


contract TestMerkleTree
{
	using MerkleTree for MerkleTree.Data;

	function testUniqueLeafs ()
		public
	{
		Assert.equal(MerkleTree.GetUniqueLeaf(20, 20, 0), 6738165491478210350639451800403024427867073896603076888955948358229240057870, "Unique leaf mismatch!");
	}

	MerkleTree.Data tree1;

	function testTreeInsert ()
		public
	{
		tree1.Insert(3703141493535563179657531719960160174296085208671919316200479060314459804651);

		tree1.Insert(134551314051432487569247388144051420116740427803855572138106146683954151557);

		Assert.equal(tree1.GetRoot(), 12880293998234311228895747943713504338160238149993004139365982527556885579681, "Root mismatch!");
	}
}
