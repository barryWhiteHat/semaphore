import unittest


from ethsnarks.field import FQ
from ethsnarks.jubjub import Point


class TestJubjub(unittest.TestCase):
	def _point_a(self):
		x = 0x274dbce8d15179969bc0d49fa725bddf9de555e0ba6a693c6adb52fc9ee7a82c
		y = 0x5ce98c61b05f47fe2eae9a542bd99f6b2e78246231640b54595febfd51eb853
		return Point(FQ(x), FQ(y))

	def _point_a_double(self):
		x = 6890855772600357754907169075114257697580319025794532037257385534741338397365
		y = 4338620300185947561074059802482547481416142213883829469920100239455078257889
		return Point(FQ(x), FQ(y))

	def test_double_via_add(self):
		print("Affible Double (via add):")
		a = self._point_a()
		FQ._reset_counts()
		a_dbl = a.add(a)
		FQ._print_counts()
		self.assertEqual(a_dbl.as_point(), self._point_a_double())

	def test_etec_double(self):
		print("ETEC Double:")
		a = self._point_a().as_etec()
		FQ._reset_counts()
		a_dbl = a.double()
		FQ._print_counts()
		self.assertEqual(a_dbl.as_point(), self._point_a_double())

	def test_etec_double_via_add(self):
		print("ETEC Double (via add):")
		a = self._point_a().as_etec()
		FQ._reset_counts()
		a_dbl = a.add(a)
		FQ._print_counts()
		self.assertEqual(a_dbl.as_point(), self._point_a_double())

	def test_projective_double(self):
		print("Projected Double:")
		b = self._point_a().as_proj()
		FQ._reset_counts()
		b_dbl = b.double()
		FQ._print_counts()
		self.assertEqual(b_dbl.as_point(), self._point_a_double())

	def test_projective_double_via_add(self):
		print("Projected Double (via add):")
		c = self._point_a().as_proj()
		FQ._reset_counts()
		c_dbl = c.add(c)
		FQ._print_counts()
		self.assertEqual(c_dbl.as_point(), self._point_a_double())

	def test_mult_2(self):
		print("Etec Mult 2")
		p = self._point_a().as_etec()
		FQ._reset_counts()
		q = p.mult(2)
		FQ._print_counts()
		self.assertEqual(q.as_point(), self._point_a_double())

	def test_etec_mult_n(self):
		print("ETEC Mult n")
		p = self._point_a().as_etec()
		FQ._reset_counts()
		q = p.mult(6890855772600357754907169075114257697580319025794532037257385534741338397365)
		FQ._print_counts()
		q = q.as_point()
		self.assertEqual(q.x, 6317123931401941284657971611369077243307682877199795030160588338302336995127)
		self.assertEqual(q.y, 17705894757276775630165779951991641206660307982595100429224895554788146104270)

	def test_proj_mult_n(self):
		print("Projective Mult n")
		p = self._point_a().as_proj()
		FQ._reset_counts()
		q = p.mult(6890855772600357754907169075114257697580319025794532037257385534741338397365)
		FQ._print_counts()
		q = q.as_point()
		self.assertEqual(q.x, 6317123931401941284657971611369077243307682877199795030160588338302336995127)
		self.assertEqual(q.y, 17705894757276775630165779951991641206660307982595100429224895554788146104270)


if __name__ == "__main__":
	unittest.main()
