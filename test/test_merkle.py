import unittest

import hashlib
from ethsnarks.merkletree import MerkleTree, MerkleHasherLongsight
from ethsnarks.field import SNARK_SCALAR_FIELD


class TestMerkleTree(unittest.TestCase):
    def test_tree(self):
        n_items = 32
        tree = MerkleTree(n_items)
        self.assertEqual(tree.root, None)
        self.assertEqual(len(tree), 0)

        previous_root = None
        hasher = hashlib.sha256()
        for n in range(0, n_items):
            hasher.update(bytes([n]) * 32)
            item = int.from_bytes(hasher.digest(), 'big') % SNARK_SCALAR_FIELD
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

        self.assertEqual(tree.root, 13981856331482487152452149678096232821987624395720231314895268163963385035507)

        proof_a = tree.proof(0)
        self.assertEqual(proof_a.path, [item_b])

        proof_b = tree.proof(1)
        self.assertEqual(proof_b.path, [item_a])

    def test_known_2pow28(self):
        tree = MerkleTree(2<<28)

        item_a = 3703141493535563179657531719960160174296085208671919316200479060314459804651
        tree.append(item_a)

        item_b = 134551314051432487569247388144051420116740427803855572138106146683954151557
        tree.append(item_b)

        self.assertEqual(tree.root, 12880293998234311228895747943713504338160238149993004139365982527556885579681)

    def test_uniques(self):
        hasher = MerkleHasherLongsight(29)
        self.assertEqual(hasher.unique(20, 20), 6738165491478210350639451800403024427867073896603076888955948358229240057870)

if __name__ == "__main__":
    unittest.main()
