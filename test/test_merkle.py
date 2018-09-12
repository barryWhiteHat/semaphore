import unittest

import hashlib
from ethsnarks.merkletree import MerkleTree, curve_order


class TestMerkleTree(unittest.TestCase):
    def test_tree(self):
        n_items = 100
        tree = MerkleTree(n_items)
        self.assertEqual(tree.root, None)
        self.assertEqual(len(tree), 0)

        previous_root = None
        hasher = hashlib.sha256()
        for n in range(0, n_items):
            hasher.update(bytes([n]) * 32)
            item = int.from_bytes(hasher.digest(), 'big') % curve_order
            tree.append(item)
            self.assertEqual(len(tree), n + 1)
            self.assertNotEqual(tree.root, previous_root)
            previous_root = tree.root
            proof = tree.proof(n)
            self.assertTrue(proof.verify(tree.root))

            # Then verify all existing items can also be proven to be in the tree
            for m in range(0, len(tree) - 1):
                self.assertTrue(tree.proof(m).verify(tree.root))

    def test_known1(self):
        tree = MerkleTree(2)

        item_a = 3703141493535563179657531719960160174296085208671919316200479060314459804651
        tree.append(item_a)

        item_b = 134551314051432487569247388144051420116740427803855572138106146683954151557
        tree.append(item_b)

        self.assertEqual(tree.root, 12232803403448551110711645741717605608347940439638387632993385741901727947062)

        proof_a = tree.proof(0)
        self.assertEqual(proof_a.path, [item_b])

        proof_b = tree.proof(1)
        self.assertEqual(proof_b.path, [item_a])


if __name__ == "__main__":
    unittest.main()
