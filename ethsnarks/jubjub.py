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

------------------

This also implements the mixed Edwards-Montgomery representation described in the
paper:

 "Efficient arithmetic on elliptic curves using a mixed Edwards-Montgomery represetation"
 - https://eprint.iacr.org/2008/218.pdf
   Wouter Gastryck, Steven Galbraith and Reza Rezaeian Farashahi
"""

from collections import namedtuple

from .field import FQ

JUBJUB_A = 168700
JUBJUB_D = 168696

MONT_A = 168698		#  2 * (JUBJUB_A + JUBJUB_D) / (JUBJUB_A - JUBJUB_D)
MONT_B = 1			#  4 / (JUBJUB_A - JUBJUB_D)


class AbstractCurveOps(object):
	def mult(self, scalar):
		p = self
		a = self.zero()
		while scalar != 0:
			if (scalar & 1) != 0:
				a = a.add(p)
			p = p.double()
			scalar = scalar // 2
		return a


class Point(AbstractCurveOps, namedtuple('_Point', ('x', 'y'))):
	def as_proj(self):
		return ProjPoint(self.x, self.y, 1)

	def as_etec(self):
		return EtecPoint(self.x, self.y, self.x*self.y, 1)

	def as_mont(self):
		"""
		From IACR 2008/218 section 2:

		Every Edwards form is birationally equivalent to a Montgomery form via:

			E_d --> M_{(2(1+d)/(1-d))} : (x,y) -> ((1+y)/(1-y), x * ((1+y)/(1-y)))
		"""
		delta = (1+self.y) / (1-self.y)
		return MontPoint(delta, self.x * delta)

	def as_point(self):
		return self

	def double(self):
		return self.add(self)

	def add(self, other):
		if self.x == 0 and self.y == 0:
			return other
		(u1, v1) = (self.x, self.y)
		(u2, v2) = (other.x, other.y)
		u3 = (u1*v2 + v1*u2) / (FQ.one() + JUBJUB_D*u1*u2*v1*v2)
		v3 = (v1*v2 - JUBJUB_A*u1*u2) / (FQ.one() - JUBJUB_D*u1*u2*v1*v2)
		return Point(u3, v3)

	def one(self):
		return Point(0, 1)

	def zero(self):
		return Point(0, 0)


class MontPoint(AbstractCurveOps, namedtuple('_MontPoint', ('a', 'b'))):
	def as_point(self):
		"""
		From IACR 2008/218 section 2:

		Every Edwards form is birationally equivalent to a Montgomery form via:			
			M_{(2(1+d)/(1-d))} --> E_d : (x,y) -> (x/y, (x-1)/(x+1))
		"""
		x = self.b / self.a
		y = (self.a - 1) / (self.a + 1)
		return Point(x, y)


class ProjPoint(AbstractCurveOps, namedtuple('_ProjPoint', ('x', 'y', 'z'))):
	def as_proj(self):
		return self

	def as_etec(self):
		return EtecPoint(self.x, self.y, self.x*self.y, self.z)

	def as_point(self):
		assert self.z != 0
		inv_z = self.z.inv()
		return Point(self.x*inv_z, self.y*inv_z)

	def one(self):
		return Point(0, 1)

	def zero(self):
		return Point(0, 0)

	def add(self, other):
		"""
		add-2008-bbjlp
		https:/eprint.iacr.org/2008/013 Section 6
		Strongly unified
		"""
		assert isinstance(other, ProjPoint)
		a = self.z * other.z
		b = a * a
		c = self.x * other.x
		d = self.y * other.y
		t0 = c * d
		e = JUBJUB_D * t0
		f = b - e
		g = b + e
		t1 = self.x + self.y
		t2 = other.x + other.y
		t3 = t1 * t2
		t4 = t3 - c
		t5 = t4 - d
		t6 = f * t5
		x3 = a * t6
		t7 = JUBJUB_A * c
		t8 = d - t7
		t9 = g * t8
		y3 = a * t9
		z3 = f * g
		return ProjPoint(x3, y3, z3)

	def double(self):
		"""
		dbl-2008-bbjlp https://eprint.iacr.org/2008/013

		From "Twisted Edwards Curves" - BBJLP

		# Doubling in Projective Twisted Coordinates
		> The following formulas compute (X3 : Y3 : Z3) = 2(X1 : Y1 : Z1)
		> in 3M + 4S + 1D + 7add, where the 1D is a multiplication by `a`.
		"""
		t0 = self.x + self.y
		b = t0 * t0
		c = self.x * self.x
		d = self.y * self.y
		e = JUBJUB_A * c
		f = e + d
		h = self.z * self.z
		t1 = 2 * h
		j = f - t1
		t2 = b - c
		t3 = t2 - d
		x3 = t3 * j
		t4 = e - d
		y3 = f * t4
		z3 = f * j
		return ProjPoint(x3, y3, z3)


class EtecPoint(AbstractCurveOps, namedtuple('_EtecPoint', ('x', 'y', 't', 'z'))):
	def as_etec(self):
		return self

	def as_point(self):
		assert self.z != 0
		inv_z = self.z.inv()
		return Point(self.x*inv_z, self.y*inv_z)

	def zero(self):
		return EtecPoint(0, 0, 0, 0)

	def one(self):
		return EtecPoint(0, 1, 0, 1)

	def double(self):
		"""
		dbl-2008-hwcd
		"""
		a = self.x * self.x
		b = self.y * self.y
		t0 = self.z * self.z
		c = t0 * 2
		d = JUBJUB_A * a
		t1 = self.x + self.y
		t2 = t1 * t1
		t3 = t2 - a
		e = t3 - b
		g = d + b
		f = g - c
		h = d - b
		return EtecPoint(e*f, g*h, e*h, f*g)

	def add(self, other):
		"""
		3.1 Unified addition in ε^e
		"""
		assert isinstance(other, EtecPoint)
		if self.x == 0 and self.y == 0 and self.t == 0 and self.z == 0:
			return other

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
