"""
This module implements the extended twisted edwards and extended affine coordinates
described in the paper "Twisted Edwards Curves Revisited":

 - https://iacr.org/archive/asiacrypt2008/53500329/53500329.pdf
   Huseyin Hisil, Kenneth Koon-Ho Wong, Gary Carter, and Ed Dawson

   		Information Security Institute,
   		Queensland University of Technology, QLD, 4000, Australia
   		{h.hisil, kk.wong, g.carter, e.dawson}@qut.edu.au

By using the extended coordinate system we can avoid expensive modular exponentiation
calls, for example - a scalar multiplication call (or multiple...) may perform only
one 3d->2d projection at the point where affine coordinates are necessary, and every
intermediate uses a much faster form.
"""

from collections import namedtuple

from .field import FQ

JUBJUB_A = 168700
JUBJUB_D = 168696


def as_fq(whut):
	if isinstance(whut, FQ):
		return whut
	return FQ(whut)


class Point(namedtuple('_Point', ('x', 'y'))):
	def as_jc(self):
		return EacPoint(self.x, self.y, 1)

	def as_etec(self):
		return EtecPoint(self.x, self.y, self.x*self.y, 1)

	def as_point(self):
		return self

	def double(self):
		return self.as_etec().double()

	def add(self, other):
		if self.x == 0 and self.y == 0:
			return other
		return self.as_etec().add(other)

	def one(self):
		return Point(0, 1)

	def zero(self):
		return Point(0, 0)

	def mult(self, scalar):
		return self.as_etec().mult(scalar)


class JcPoint(namedtuple('_JcPoint', ('x', 'y', 'z'))):
	def as_jc(self):
		return self

	def as_etec(self):
		return EtecPoint(self.x, self.y, self.x*self.y, self.z)

	def as_point(self):
		assert self.z != 0
		return Point(self.x/self.z, self.y/self.z)

	def double(self):
		return self.as_etec().double()

	def add(self, other):
		if self.x == 0 and self.y == 0 and self.z == 0:
			return other
		return self.as_etec().add(other)

	def zero(self):
		return EacPoint(0, 0, 0)

	def one(self):
		return EacPoint(0, 1, 1)

	def mult(self, scalar):
		return self.as_etec().mult(scalar)


class EtecPoint(namedtuple('_EtecPoint', ('x', 'y', 't', 'z'))):
	def as_jc(self):
		return JcPoint(self.x, self.y, self.z)

	def as_etec(self):
		return self

	def as_point(self):
		assert self.z != 0
		return Point(self.x/self.z, self.y/self.z)

	def zero(self):
		return EtecPoint(0, 0, 0, 0)

	def one(self):
		return EtecPoint(0, 1, 0, 1)

	def double(self):
		return self.add(self)

	def add(self, other):
		"""
		3.1 Unified addition in ε^e
		"""
		if self.x == 0 and self.y == 0 and self.t == 0 and self.z == 0:
			return other

		other = other.as_etec()
		assert self.z != 0
		assert other.z != 0

		a = self.x * other.x
		b = self.y * other.y
		c = (JUBJUB_D * self.t) * other.t
		d = self.z * other.z
		e = ((self.x + self.y) * (other.x + other.y)) - a - b
		f = d - c
		g = d + c
		h = b - (JUBJUB_A * a)

		return EtecPoint(e*f, g*h, e*h, f*g)

	def mult(self, scalar):
		p = self
		a = self.zero()
		while scalar != 0:
			if (scalar & 1) != 0:
				a = a.add(p)
			p = p.double()
			scalar = scalar // 2
		return a
