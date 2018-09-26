import unittest


from ethsnarks.field import FQ
from ethsnarks.jubjub import Point


class TestJubjub(unittest.TestCase):
	def _point_a(self):
		x = 0x274dbce8d15179969bc0d49fa725bddf9de555e0ba6a693c6adb52fc9ee7a82c
		y = 0x5ce98c61b05f47fe2eae9a542bd99f6b2e78246231640b54595febfd51eb853
		return Point(FQ(x), FQ(y))
		
	def test_double(self):
		p = self._point_a()
		q = p.double().as_point()
		self.assertEqual(q.x, 6890855772600357754907169075114257697580319025794532037257385534741338397365)
		self.assertEqual(q.y, 4338620300185947561074059802482547481416142213883829469920100239455078257889)

	def test_mult_2(self):
		p = self._point_a()
		q = p.mult(2).as_point()
		self.assertEqual(q.x, 6890855772600357754907169075114257697580319025794532037257385534741338397365)
		self.assertEqual(q.y, 4338620300185947561074059802482547481416142213883829469920100239455078257889)


if __name__ == "__main__":
	unittest.main()
