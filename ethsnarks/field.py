# Code copied from https://github.com/ethereum/py_ecc/blob/master/py_ecc/bn128/bn128_curve.py
#
# The MIT License (MIT)
#
# Copyright (c) 2015 Vitalik Buterin
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#

import sys
from random import randint

# python3 compatibility
if sys.version_info.major == 2:
    int_types = (int, long)  # noqa: F821
else:
    int_types = (int,)


SNARK_SCALAR_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617

# Extended euclidean algorithm to find modular inverses for
# integers
def inv(a, n):
    if a == 0:
        return 0
    lm, hm = 1, 0
    low, high = a % n, n
    while low > 1:
        r = high // low
        nm, new = hm - lm * r, high - low * r
        lm, low, hm, high = nm, new, lm, low
    return lm % n


# A class for field elements in FQ. Wrap a number in this class,
# and it becomes a field element.
class FQ(object):
    __slots__ = ('n', 'm')

    def __init__(self, n, field_modulus=SNARK_SCALAR_FIELD):
        self.m = field_modulus
        if isinstance(n, self.__class__):
            self.n = n.n
        else:
            self.n = n % self.m
        assert isinstance(self.n, int_types)

    def _other_n(self, other):
        if isinstance(other, FQ):
            if other.m != self.m:
                raise RuntimeError("Other field element has different modulus")
            return other.n
        if not isinstance(other, int_types):
            raise RuntimeError("Not a valid value type: " + str(type(other).__name__))
        return other

    def __add__(self, other):
        on = self._other_n(other)
        return FQ((self.n + on) % self.m, self.m)

    def __mul__(self, other):
        on = self._other_n(other)
        return FQ((self.n * on) % self.m, self.m)

    def __rmul__(self, other):
        return self * other

    def __radd__(self, other):
        return self + other

    def __rsub__(self, other):
        on = self._other_n(other)
        return FQ((on - self.n) % self.m, self.m)

    def __sub__(self, other):
        on = self._other_n(other)
        return FQ((self.n - on) % self.m, self.m)

    def __div__(self, other):
        on = self._other_n(other)
        return FQ(self.n * inv(on, self.m) % self.m, self.m)

    def __truediv__(self, other):
        return self.__div__(other)

    def __rdiv__(self, other):
        on = self._other_n(other)
        return FQ(inv(self.n, self.m) * on % self.m, self.m)

    def __rtruediv__(self, other):
        return self.__rdiv__(other)

    def __pow__(self, other):
        if other == 0:
            return FQ(1, self.m)
        elif other == 1:
            return FQ(self.n, self.m)
        elif other % 2 == 0:
            return (self * self) ** (other // 2)
        else:
            return ((self * self) ** int(other // 2)) * self

    def __eq__(self, other):
        if other == 0.:
            other = 0
        return self.n == self._other_n(other)

    def __ne__(self, other):
        return not self == other

    def __neg__(self):
        return FQ(-self.n, self.m)

    def __repr__(self):
        return repr(self.n)

    @classmethod
    def random(cls, modulus=SNARK_SCALAR_FIELD):        
        return FQ(randint(1, modulus - 1), modulus)

    @classmethod
    def one(cls, modulus=SNARK_SCALAR_FIELD):
        return cls(1, modulus)

    @classmethod
    def zero(cls, modulus=SNARK_SCALAR_FIELD):
        return cls(0, modulus)
