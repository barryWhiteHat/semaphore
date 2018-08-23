import unittest

import hashlib
from ethsnarks.merkletree import MerkleTree, MerkleHasherLongsightF, MerkleHasherSHA256, curve_order


class TestMerkleTree(unittest.TestCase):
    def test_incremental_sha256(self):
        n_items = 100
        tree = MerkleTree(n_items, MerkleHasherSHA256)
        self.assertEqual(tree.root, None)
        self.assertEqual(len(tree), 0)

        previous_root = None
        for n in range(0, n_items):
            item = bytes([n]) * 32
            tree.append(item)
            self.assertEqual(len(tree), n + 1)

            self.assertNotEqual(tree.root, previous_root)
            previous_root = tree.root
            proof = tree.proof(n)
            self.assertTrue(proof.verify(tree.root))

            # Then verify all existing items can also be proven to be in the tree
            for m in range(0, len(tree) - 1):
                self.assertTrue(tree.proof(m).verify(tree.root))

    def test_incremental_longsight(self):
        n_items = 100
        tree = MerkleTree(n_items, MerkleHasherLongsightF)
        self.assertEqual(tree.root, None)
        self.assertEqual(len(tree), 0)

        previous_root = None
        for n in range(0, n_items):
            hasher = hashlib.sha256()
            hasher.update(bytes([n]) * 32)
            item = int.from_bytes(hasher.digest(), 'little') % curve_order
            tree.append(item)
            self.assertEqual(len(tree), n + 1)

            self.assertNotEqual(tree.root, previous_root)
            previous_root = tree.root
            proof = tree.proof(n)
            self.assertTrue(proof.verify(tree.root))

            # Then verify all existing items can also be proven to be in the tree
            for m in range(0, len(tree) - 1):
                self.assertTrue(tree.proof(m).verify(tree.root))


if __name__ == "__main__":
    unittest.main()
