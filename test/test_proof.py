import unittest

import random
import json
import time

from ethsnarks.verifier import VerifyingKey, Proof
from ethsnarks.deploy import genWitness, tree_depth, native_verify
from ethsnarks.utils import genMerkelTree, sha256, initMerkleTree


VK_FILENAME = 'zksnark_element/vk.json'
PK_FILENAME = 'zksnark_element/pk.raw'


class ProofTests(unittest.TestCase):
    def test_proof_gen(self):
        leaves, nullifiers, sks = initMerkleTree(2) 
        root, layers = genMerkelTree(tree_depth, leaves)
        signal_variables = sha256(str(1))
        external_nullifier = sha256("nomimatedSpokesPerson"+root+str(time.time()))
        signal1 = sha256({"NomimatedSpokesPersonFor":root , "candidate": "Candidate1" })
        proof = None

        with open('zksnark_element/vk.json', 'r') as handle:
            vk = VerifyingKey.from_dict(json.load(handle))

        for address, (nullifier , sk) in enumerate(zip(nullifiers, sks)):
            rand = int(random.uniform(1, 3)) 
            print("Generating witness")
            proof_data, proof_root = genWitness(leaves, nullifier, sk, signal1 , signal_variables, external_nullifier, address, tree_depth, 0, PK_FILENAME)
            proof = Proof.from_dict(proof_data)
            print("Proof:", proof)
            self.assertTrue(native_verify(vk.to_json(), proof.to_json()))
            break


if __name__ == "__main__":
    unittest.main()
