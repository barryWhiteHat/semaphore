pragma solidity ^0.4.24;

import "./LongsightL.sol";

library MerkleTree
{
    // ceil(log2(2<<28))
    uint constant public tree_depth = 29;


    // 2<<28 leaves
    uint constant public MaxLeafCount = 536870912;


    struct Data
    {
        uint cur;
        mapping (uint256 => bool) roots;
        uint256[536870912][30] leaves;
    }


    function HashImpl (uint256 left, uint256 right)
        internal pure returns (uint256)
    {
        // XXX: it is inefficient to fill the constants every time!
        uint256[10] memory C;
        LongsightL.ConstantsL12p5(C);

        uint256 IV = 0;

        return LongsightL.LongsightL12p5_MP([left, right], IV, C);
    }


    function Insert(Data storage self, uint256 com)
        internal returns (bool)
    {
        uint256 offset = self.cur;

        require (offset != MaxLeafCount - 1);

        self.leaves[0][offset] = com;

        UpdateTree(self);

        self.cur = offset + 1;
   
        return true;
    }


    function GetProof(Data storage self, uint index)
        internal view returns (uint256[29], bool[29])
    {
        bool[29] memory address_bits;

        uint256[29] memory proof_path;

        for (uint i=0 ; i < tree_depth; i++)
        {
            address_bits[i] = index % 2 == 0 ? false : true;

            if (index%2 == 0)
            {
                proof_path[i] = GetUniqueLeaf(self.leaves[i][index + 1], i);
            }
            else {
                proof_path[i] = GetUniqueLeaf(self.leaves[i][index - 1], i);
            }

            index = uint(index / 2);
        }

        return(proof_path, address_bits);
    }


    function GetUniqueLeaf(uint256 leaf, uint depth)
        internal pure returns (uint256)
    {
        if (leaf == 0x0)
        {
            for (uint i=0; i < depth; i++)
            {
                leaf = HashImpl(leaf, leaf);
            }
        }

        return(leaf);
    }


    function UpdateTree(Data storage self)
        internal returns(uint256 root)
    {
        uint CurrentIndex = self.cur;

        uint256 leaf1;

        uint256 leaf2;

        for (uint i=0 ; i < tree_depth; i++)
        {
            uint NextIndex = uint(CurrentIndex/2);

            if (CurrentIndex%2 == 0)
            {
                leaf1 = self.leaves[i][CurrentIndex];

                leaf2 = GetUniqueLeaf(self.leaves[i][CurrentIndex + 1], i);
            }
            else
            {
                leaf1 = GetUniqueLeaf(self.leaves[i][CurrentIndex - 1], i);

                leaf2 = self.leaves[i][CurrentIndex];
            }

            self.leaves[i+1][NextIndex] = HashImpl(leaf1, leaf2);

            CurrentIndex = NextIndex;
        }

        return self.leaves[tree_depth][0];
    }
    
   
    function GetLeaf(Data storage self, uint depth, uint offset)
        internal view returns (uint256)
    {
        return self.leaves[depth][offset];
    }


    function GetRoot (Data storage self)
        internal view returns(uint256)
    {
        return self.leaves[tree_depth][0];
    }
}