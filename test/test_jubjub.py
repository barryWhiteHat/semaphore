import unittest

from os import urandom

from ethsnarks.field import FQ
from ethsnarks.jubjub import Point, EtecPoint, ProjPoint, JUBJUB_L, JUBJUB_C


class TestJubjub(unittest.TestCase):
	def _point_r(self):
		return Point.from_hash(urandom(10))
	def _point_a(self):
		x = 0x274dbce8d15179969bc0d49fa725bddf9de555e0ba6a693c6adb52fc9ee7a82c
		y = 0x5ce98c61b05f47fe2eae9a542bd99f6b2e78246231640b54595febfd51eb853
		return Point(FQ(x), FQ(y))

	def _point_a_double(self):
		x = 6890855772600357754907169075114257697580319025794532037257385534741338397365
		y = 4338620300185947561074059802482547481416142213883829469920100239455078257889
		return Point(FQ(x), FQ(y))

	def test_validity(self):
		self.assertTrue(self._point_a().valid())
		self.assertTrue(Point.infinity().valid())

	def test_hash_to_point(self):
		p = Point.from_hash(b'test')
		expected = Point(x=14447835080060184026016688399206371580541195409649120233292541285797925116718, y=6491210871329023843020152497494661717176702609200142392074344830880218876421)
		self.assertEqual(p, expected)

		for _ in range(0, 10):
			entropy = urandom(10)
			p = Point.from_hash(entropy)

	def test_recover_x(self):
		for _ in range(0, 10):
			p = self._point_r()
			q = Point.from_y(p.y)
			self.assertEqual(p, q)

	def test_recover_y(self):
		for _ in range(0, 10):
			p = self._point_r()
			q = Point.from_x(p.x)
			self.assertEqual(p.x, q.x)
			self.assertTrue(p.y in [q.y, -q.y])

	def test_negate(self):
		p = self._point_a()
		for q in [p.as_point(), p.as_etec(), p.as_proj()]:
			r = q.add( q.neg() )
			self.assertEqual(r.as_point(), p.infinity())

	def test_zero(self):
		"""
		Verify that operations on infinity result in infinity
		"""
		zero = Point.infinity()
		etec_zero = EtecPoint.infinity()
		proj_zero = ProjPoint.infinity()

		self.assertEqual(zero.as_etec(), etec_zero)
		self.assertEqual(zero.as_proj(), proj_zero)

		self.assertEqual(etec_zero.as_point(), zero)
		self.assertEqual(etec_zero.as_proj(), proj_zero)

		self.assertEqual(proj_zero.as_point(), zero)
		self.assertEqual(proj_zero.as_etec(), etec_zero)

		self.assertEqual(zero.add(zero), zero)
		self.assertEqual(etec_zero.add(etec_zero), etec_zero)
		self.assertEqual(proj_zero.add(proj_zero), proj_zero)

		self.assertEqual(zero.double(), zero)
		self.assertEqual(etec_zero.double(), etec_zero)
		self.assertEqual(proj_zero.double(), proj_zero)

	def test_double_via_add(self):
		a = self._point_a()
		a_dbl = a.add(a)
		self.assertEqual(a_dbl.as_point(), self._point_a_double())

	def test_etec_double(self):
		a = self._point_a().as_etec()
		a_dbl = a.double()
		self.assertEqual(a_dbl.as_point(), self._point_a_double())

	def test_twist(self):
		"""
		Any point, multiplied by L results in a low-order point
		Multiplying again by L results in the same point
		The resulting point, multiplied by the cofactor results in infinity
		"""
		p = self._point_r()
		for q in [p.as_point(), p.as_proj(), p.as_etec()]:
			r = q.mult(JUBJUB_L).as_point()
			s = r.mult(JUBJUB_L).as_point()
			self.assertEqual(r, s)
			self.assertEqual(s.mult(JUBJUB_C), s.infinity())

	def test_equality(self):
		p = self._point_a()
		for q in [p.as_point(), p.as_proj(), p.as_etec()]:
			a = q.mult(9).add(q.mult(5))
			b = q.mult(12).add(q.mult(2))

			self.assertTrue(a.as_point().valid())
			self.assertTrue(b.as_point().valid())
			self.assertTrue(a.valid())
			self.assertTrue(b.valid())
			self.assertEqual(a.as_point(), b.as_point())

	def test_etec_double_via_add(self):
		a = self._point_a().as_etec()
		a_dbl = a.add(a)
		self.assertEqual(a_dbl.as_point(), self._point_a_double())

	def test_projective_double(self):
		b = self._point_a().as_proj()
		b_dbl = b.double()
		self.assertEqual(b_dbl.as_point(), self._point_a_double())

	def test_projective_double_via_add(self):
		c = self._point_a().as_proj()
		c_dbl = c.add(c)
		self.assertEqual(c_dbl.as_point(), self._point_a_double())

	def test_mult_2(self):
		p = self._point_a().as_etec()
		q = p.mult(2)
		self.assertEqual(q.as_point(), self._point_a_double())

	def test_etec_mult_n(self):
		p = self._point_a().as_etec()
		q = p.mult(6890855772600357754907169075114257697580319025794532037257385534741338397365)
		q = q.as_point()
		self.assertEqual(q.x, 6317123931401941284657971611369077243307682877199795030160588338302336995127)
		self.assertEqual(q.y, 17705894757276775630165779951991641206660307982595100429224895554788146104270)

	def test_proj_mult_n(self):
		p = self._point_a().as_proj()
		q = p.mult(6890855772600357754907169075114257697580319025794532037257385534741338397365)
		q = q.as_point()
		self.assertEqual(q.x, 6317123931401941284657971611369077243307682877199795030160588338302336995127)
		self.assertEqual(q.y, 17705894757276775630165779951991641206660307982595100429224895554788146104270)


if __name__ == "__main__":
	unittest.main()
