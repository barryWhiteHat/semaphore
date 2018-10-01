import unittest

from os import urandom

from ethsnarks.field import FQ
from ethsnarks.jubjub import Point, MontPoint, EtecPoint, ProjPoint, JUBJUB_L, JUBJUB_C, MONT_A, MONT_B
from ethsnarks.numbertheory import SquareRootError


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

	def test_1_negation2(self):
		for _ in range(0, 10):
			p = self._point_r()
			q = Point(p.x, -p.y)
			r = Point(-p.x, p.y)

	def test_2_mont_form(self):
		for p in [self._point_r(), self._point_a()]:
			d = p.double().as_point()
			q = p.as_mont()
			r = q.as_point()
			self.assertEqual(p, r)
			self.assertTrue(r.valid())
			#self.assertTrue(q.valid())

	def test_3_validity(self):
		self.assertTrue(self._point_a().valid())
		self.assertTrue(Point.infinity().valid())
		self.assertTrue(EtecPoint.infinity().valid())
		self.assertTrue(ProjPoint.infinity().valid())

	def test_5_recover_x(self):
		"""
		There is one x point for every y
		"""
		for _ in range(0, 10):
			p = self._point_r()
			q = Point.from_y(p.y)
			self.assertEqual(p, q)

	def test_6_recover_y(self):
		"""
		There are two y points for every x
		"""
		for _ in range(0, 10):
			p = self._point_r()
			q = Point.from_x(p.x)
			self.assertEqual(p.x, q.x)
			self.assertTrue(p.y in [q.y, -q.y])

	def test_7_negate(self):
		"""
		Addition of its own negative results in infinity
		"""
		p = self._point_a()
		for q in [p.as_point(), p.as_etec(), p.as_proj()]:
			r = q.add( q.neg() )
			self.assertEqual(r.as_point(), p.infinity())

	def test_8_hash_to_point(self):
		p = Point.from_hash(b'test')
		expected = Point(x=14447835080060184026016688399206371580541195409649120233292541285797925116718, y=6491210871329023843020152497494661717176702609200142392074344830880218876421)
		self.assertEqual(p, expected)

		for _ in range(0, 10):
			entropy = urandom(10)
			p = Point.from_hash(entropy)

	def test_9_zero(self):
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

	def test_10_twist(self):
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

	def test_11_exceptional_points(self):
		"""
		The point (0,0) on E_{M,A,B} corresponds to the affine point of order 2
		on E_{E,a,d}, namely (0, -1). This point and (0,1) are the only exception
		points of the inverse map of (x,y) -> ((1+y)/(1-y),(1+y)/(1-y)x), where (0,1)
		is mapped to the point at infinity.
		"""
		p = MontPoint(FQ(0),FQ(0))
		q = p.as_point()
		self.assertEqual(q.x, FQ(0))
		self.assertEqual(q.y, FQ(-1))

		r = MontPoint(FQ(0), FQ(1))
		s = r.as_point()
		self.assertEqual(s.x, FQ(0))
		self.assertEqual(s.y, FQ(-1))

	def test_12_nonsquares(self):
		"""
		If (A+2)*(A-2) is a square (e.g. if `ad` is a square) then there are two more
		points with v=0. These points have order 2
		"""
		try:
			x = (MONT_A+2) * (MONT_A-2)
			FQ(int(x)).sqrt()
			self.assertTrue(False)
		except SquareRootError:
			pass

		"""
		If (A-2)/B is a square (e.g. if `d` is a square) then there are two points
		with `u=-1`. These points have order 4. These points correspond to two points
		of order 4 at infinity of the desingularization of E_{E,a,d}
		"""
		try:
			x = (MONT_A-2) / MONT_B
			FQ(int(x)).sqrt()
			self.assertTrue(False)
		except SquareRootError:
			pass

	def test_13_equality(self):
		p = self._point_a()
		for q in [p.as_point(), p.as_proj(), p.as_etec()]:
			a = q.mult(9).add(q.mult(5))
			b = q.mult(12).add(q.mult(2))

			self.assertTrue(a.as_point().valid())
			self.assertTrue(b.as_point().valid())
			self.assertTrue(a.valid())
			self.assertTrue(b.valid())
			self.assertEqual(a.as_point(), b.as_point())

	"""
	def test_14_mont_double_via_add(self):
		p = self._point_a().as_mont_2()
		p_dbl = p.add(p)

		q = self._point_a().as_mont()
		q_dbl = q.add(q)

		a_dbl = self._point_a_double()

		print(p_dbl)
		print(q_dbl)
		print(a_dbl.as_mont())
	"""

	"""
	def test_15_random_mont_clock(self):
		for _ in range(0, 10):
			r = self._point_r().as_mont()
			self.assertTrue(r.valid())
	"""

	def test_double_via_add(self):
		a = self._point_a()
		a_dbl = a.add(a)
		self.assertEqual(a_dbl.as_point(), self._point_a_double())

	def test_etec_double(self):
		a = self._point_a().as_etec()
		a_dbl = a.double()
		self.assertEqual(a_dbl.as_point(), self._point_a_double())

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
