import unittest

from os import urandom

from ethsnarks.mod.hashpreimage import HashPreimage


VK_FILENAME = 'zksnark_element/hpi.vk.json'
PK_FILENAME = 'zksnark_element/hpi.pk.raw'
SO_FILENAME = 'build/src/libhashpreimage.so'


class HashPreimageTests(unittest.TestCase):
    def test_prove_verify(self):
        hpi = HashPreimage(SO_FILENAME, VK_FILENAME, PK_FILENAME)
        preimage = urandom(64)
        proof = hpi.prove(preimage)
        self.assertTrue(hpi.verify(proof))


if __name__ == "__main__":
    unittest.main()
