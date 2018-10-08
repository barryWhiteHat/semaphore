import unittest
from os import urandom


from ethsnarks.jubjub import JUBJUB_L, Point, FQ
from ethsnarks.eddsa import eddsa_sign, eddsa_verify


class TestEdDSA(unittest.TestCase):
	def test_signverify(self):
		B = Point.from_hash(b'eddsa_base')
		k = FQ.random(JUBJUB_L)
		A = B * k
		m = urandom(32)
		R, s = eddsa_sign(m, k, B, A)

		self.assertTrue(eddsa_verify(A, R, s, m, B))


if __name__ == "__main__":
	unittest.main()
