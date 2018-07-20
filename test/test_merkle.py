import unittest


from ethsnarks.utils import genMerkelTree, getMerkelProof, sha256, initMerkleTree


def verifyMerkleProof(root, path, address_bits):
    for i, node in enumerate(path):
        bit = address_bits[i]
        if bit:
            the_node = sha256(node, )


class TestMerkleTree(unittest.TestCase):
    def test_tree(self):
        tree_depth = 5
        leaves, nullifiers, sks = initMerkleTree(tree_depth) 
        root, tree = genMerkelTree(tree_depth, leaves)
        for address, (nullifier , sk) in enumerate(zip(nullifiers, sks)):
            path, address_bits = getMerkelProof(leaves, address, tree_depth)
            print(root, path, address_bits)
            #print(verifyMerkleProof(root, path, address_bits))
            # TODO: verify merkle proof

    def test_getMerkelProof(self):
        proof1, address1 =  getMerkelProof([
                "0x0000000000000000000000000000000000000000000000000000000000000000",
                "0x0000000000000000000000000000000000000000000000000000000000000000",
                "0x0000000000000000000000000000000000000000000000000000000000000000",
                "0x0000000000000000000000000000000000000000000000000000000000000000"],
                0, 2)
        self.assertEqual(proof1[0], "0x0000000000000000000000000000000000000000000000000000000000000000")
        self.assertEqual(proof1[1], "0xf5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b")
        self.assertEqual(address1[0], 0)
        self.assertEqual(address1[1], 0)

    def test_GenMerkelTree(self):
        mr1, tree = genMerkelTree(1, ["0x0000000000000000000000000000000000000000000000000000000000000000",
                                      "0x0000000000000000000000000000000000000000000000000000000000000000"])

        mr2, tree = genMerkelTree(2, ["0x0000000000000000000000000000000000000000000000000000000000000000",
                                      "0x0000000000000000000000000000000000000000000000000000000000000000", 
                                      "0x0000000000000000000000000000000000000000000000000000000000000000",
                                      "0x0000000000000000000000000000000000000000000000000000000000000000"])

        mr3, tree = genMerkelTree(29, ["0x0000000000000000000000000000000000000000000000000000000000000000",
                                       "0x0000000000000000000000000000000000000000000000000000000000000000"])

        self.assertEqual(mr1, "0xf5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b") 

        self.assertEqual(mr2, "0xdb56114e00fdd4c1f85c892bf35ac9a89289aaecb1ebd0a96cde606a748b5d71")


if __name__ == "__main__":
    unittest.main()
