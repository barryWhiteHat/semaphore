import unittest

from ethsnarks.longsight import random_element, LongsightL12p5_MP
from ethsnarks.utils import native_lib_path
from ethsnarks.mod.miximus import Miximus
from ethsnarks.merkletree import MerkleTree


NATIVE_LIB_PATH = native_lib_path('build/src/libmiximus')
VK_PATH = 'zksnark_element/miximus.vk.json'
PK_PATH = 'zksnark_element/miximus.pk.raw'


class TestMiximus(unittest.TestCase):
	def test_make_proof(self):
		n_items = 2<<28
		tree = MerkleTree(n_items)
		for n in range(0, 2):
			tree.append(random_element())

		exthash = random_element()
		nullifier = random_element()
		spend_preimage = random_element()
		spend_hash_IV = 0
		spend_hash = LongsightL12p5_MP([spend_preimage, nullifier], spend_hash_IV)
		leaf_hash_IV = 0
		leaf_hash = LongsightL12p5_MP([nullifier, spend_hash], leaf_hash_IV)
		leaf_idx = tree.append(leaf_hash)
		self.assertEqual(leaf_idx, tree.index(leaf_hash))

		# Verify it exists in true
		leaf_proof = tree.proof(leaf_idx)
		self.assertTrue(leaf_proof.verify(tree.root))

		# Generate proof		
		wrapper = Miximus(NATIVE_LIB_PATH, VK_PATH, PK_PATH)
		tree_depth = wrapper.tree_depth
		snark_proof = wrapper.prove(
			tree.root,
			nullifier,
			spend_preimage,
			exthash,
			leaf_proof.address,
			leaf_proof.path)

		self.assertTrue(wrapper.verify(snark_proof))


if __name__ == "__main__":
	unittest.main()
