import unittest

from ethsnarks.longsight import random_element, LongsightF322p5
from ethsnarks.utils import native_lib_path
from ethsnarks.mod.miximus import Miximus
from ethsnarks.merkletree import MerkleHasherLongsightF, MerkleTree


NATIVE_LIB_PATH = native_lib_path('build/src/libmiximus')
VK_PATH = 'zksnark_element/miximus.vk.json'
PK_PATH = 'zksnark_element/miximus.pk.raw'


class TestMiximus(unittest.TestCase):
	def test_make_proof(self):
		n_items = 2<<27
		tree = MerkleTree(n_items, MerkleHasherLongsightF)
		for n in range(0, 2):
			tree.append(random_element())

		exthash = random_element()
		nullifier = random_element()
		spend_preimage = random_element()
		spend_hash = LongsightF322p5(spend_preimage, nullifier)
		leaf_hash = LongsightF322p5(nullifier, spend_hash)
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
