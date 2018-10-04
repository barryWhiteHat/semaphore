import unittest

from os import urandom

from ethsnarks.field import FQ
from ethsnarks.jubjub import Point, MontPoint, EtecPoint, ProjPoint, JUBJUB_L, JUBJUB_C, MONT_A, MONT_B, JUBJUB_ORDER
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

	def test_2_mont_form(self):
		for p in [self._point_r(), self._point_a()]:
			d = p.double().as_point()
			q = p.as_mont()
			r = q.as_point()
			#self.assertEqual(p, r)
			self.assertTrue(r.valid())
			self.assertTrue(q.valid())

	def _verify_via_all(self, p):
		points = [p.as_point(), p.as_mont(), p.as_etec(), p.as_proj(), p.as_mont_xz(), p.as_edwards_yz()]
		for q in points:
			self.assertTrue(q.valid())
			qoints = [q.as_point(), q.as_mont(), q.as_etec(), q.as_proj(), q.as_mont_xz(), q.as_edwards_yz()]
			for i, r in enumerate(qoints):
				self.assertTrue(r.valid())
				self.assertEqual(r.rescale(), points[i].rescale())

	def test_3_validity(self):
		"""
		Verify that 10 random points can be converted to and from every other
		coordinate system without losing information or corruption.
		"""
		self.assertTrue(self._point_a().valid())
		self.assertTrue(Point.infinity().valid())
		self.assertTrue(EtecPoint.infinity().valid())
		self.assertTrue(ProjPoint.infinity().valid())

		for _ in range(0, 10):
			p = self._point_r()
			self._verify_via_all(p)


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
			self.assertFalse(q.is_negative())
			r = q.neg()
			self.assertTrue(r.valid())
			self.assertTrue(r.is_negative())

			self.assertEqual(q.infinity().neg(), q.infinity())

			# (x,y) + (-(x,y)) = infinity
			r = q.add( q.neg() )
			self.assertEqual(r.as_point(), p.infinity())

			# (x,y) + infinity = (x,y)
			s = q.add( q.infinity() )
			self.assertEqual(s.as_point(), q.as_point())

			# infinity + (x,y) = (x,y)
			s = q.infinity().add(q)
			self.assertEqual(s.as_point(), q.as_point())

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
		Any point, multiplied by L results in a weird point
		Multiplying again by L results in the same point
		The resulting point, multiplied by the cofactor results in infinity
		"""
		p = self._point_r()
		for q in [p.as_point(), p.as_proj(), p.as_etec()]:
			r = q.mult(JUBJUB_L).as_point()
			s = r.mult(JUBJUB_L).as_point()
			self.assertTrue(r.valid())
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
			x = int((MONT_A-2) / MONT_B)
			FQ(x).sqrt()
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

	def test_15_random_mont(self):
		for _ in range(0, 10):
			r = self._point_r().as_mont()
			self.assertTrue(r.valid())
			s = MontPoint.from_x(r.x)
			self.assertTrue(s.valid())
			self.assertEqual(s.x, r.x)
			self.assertTrue(s.y, [r.x, -r.y])

	def test_multiplicative(self):
		G = self._point_r()
		a = FQ.random()
		A = G*a
		b = FQ.random()
		B = G*b

		ab = (a.n * b.n) % JUBJUB_ORDER
		AB = G*ab
		self.assertEqual(A*b, AB)
		self.assertEqual(B*a, AB)

	def test_cyclic(self):
		G = self._point_r()
		self.assertEqual(G * (JUBJUB_ORDER+1), G)

	def test_loworder_points_mont(self):
		"""
		From "Twisted Edwards Curves" - BBJLP
		 - Exceptional Points for the Birational Equivalence

		The birational equivalence is undefined where `y = 0` or `x + 1 = 0`
		"""
		# Both Montgomery and twisted Edwards forms are valid
		# EM(0,0) -> EE(0,-1)
		p1m = MontPoint(FQ(0), FQ(0))
		p1e = p1m.as_point()
		self.assertEqual(p1e.x, FQ(0))
		self.assertEqual(p1e.y, FQ(-1))
		self.assertTrue(p1m.valid())
		self.assertTrue(p1e.valid())
		self.assertEqual(p1e.as_mont(), p1m)

		# Both Montgomery and twisted Edwards forms are valid
		# Theorem 3.4 case 1
		# EM(1, sqrt(A+2)) -> EE(?, 0)
		p2m = MontPoint(FQ(1), FQ(MONT_A+2).sqrt())
		self.assertTrue(p2m.valid())
		self.assertTrue(p2m.as_point().valid())
		self.assertEqual(p2m.as_point().as_mont(), p2m)

		# Montgomery form is invalid
		# EM(0,-1) -> EE(0,-1)
		p2m = MontPoint(FQ(0), FQ(-1))
		p2e = p2m.as_point()
		self.assertEqual(p2e.x, FQ(0))
		self.assertEqual(p2e.y, FQ(-1))
		self.assertFalse(p2m.valid())
		self.assertTrue(p2e.valid())
		self.assertNotEqual(p2e.as_mont(), p2m)

		# Montgomery form is invalid
		# EM(0,-1) -> EE(0,-1)
		p3m = MontPoint(FQ(0), FQ(1))
		p3e = p3m.as_point()
		self.assertEqual(p3e.x, FQ(0))
		self.assertEqual(p3e.y, FQ(-1))
		self.assertFalse(p3m.valid())
		self.assertTrue(p3e.valid())
		self.assertNotEqual(p3e.as_mont(), p3m)

		# Montgomery form is invalid
		# EM(-1,?) -> EE(?,0)
		p4my = FQ.random()
		p4m = MontPoint(FQ(-1), p4my)
		p4e = p4m.as_point()
		p4mb = p4e.as_mont()
		self.assertNotEqual(p4mb, p4m)
		self.assertNotEqual(p4e.x, p4my)
		self.assertEqual(p4e.y, FQ(0))
		self.assertFalse(p4m.valid())
		self.assertTrue(p3e.valid())

	def test_mont_double(self):
		"""
		Verified in Sage, using `ejubjub.py`
		Ensure that addition laws remain the same between Montgomery and Edwards coordinates
		"""
		q = Point.from_hash(b'x')
		mq = MontPoint(FQ(4828722366376575650251607168518886976429844446767098803596167689250506416759),
					   FQ(12919092401030192644826086113396919334232812611316996694878363256143428656958))
		self.assertEqual(q.as_mont(), mq)

		q2 = MontPoint(FQ(760569539648116659146730905587051427168718890872716379895718021693339839266),
					   FQ(19523163946365579499783218718995636854804792079073783994015125253921919723342))
		self.assertEqual(q.double().as_mont(), q2)

		for _ in range(0, 10):
			p = Point.from_hash(urandom(32))
			self.assertEqual(p.as_mont().double().as_edwards_yz().as_point().as_edwards_yz(), p.double().as_edwards_yz())

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
