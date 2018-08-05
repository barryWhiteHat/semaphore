# Copyright (c) 2018 HarryR
# License: LGPL-3.0+

from random import randint
from py_ecc.bn128 import curve_order


def randn(n):
    assert n > 2
    return randint(1, n-1)


def randq():
    return randn(curve_order)


def shamirs_poly_n(x, a, n):
    assert isinstance(a, (list,tuple))
    assert len(a) >= 2

    result = a[0]
    x_pow_i = x

    for i, a_i in list(enumerate(a))[1:]:
        ai_mul_xi = (a_i * x_pow_i) % n
        result = (result + ai_mul_xi) % n
        x_pow_i *= x

    return result


def shamirs_poly(x, a):
    return shamirs_poly_n(x, a, curve_order)


"""
def lagrange(points, x):
    # Borrowed from: https://gist.github.com/melpomene/2482930
    total = 0
    n = len(points)
    for i in range(n):
        xi, yi = points[i]
        def g(i, n):
            tot_mul = 1
            for j in range(n):
                if i == j:
                    continue
                xj, yj = points[j]
                # Use integer division here, versus SciPy's which uses floating point division
                # This loses precision with large values of P, which can't be easily recovered
                tot_mul *= (x - xj) // (xi - xj)
            return tot_mul
        total += yi * g(i, n)
    return total
"""

def lagrange(points, x, mod=curve_order):
    # Borrowed from: https://gist.github.com/melpomene/2482930
    total = 0
    n = len(points)
    for i in range(n):
        xi, yi = points[i]
        def g(i, n):
            tot_mul = 1
            for j in range(n):
                if i == j:
                    continue
                xj, yj = points[j]
                # Use integer division here, versus SciPy's which uses floating point division
                # This loses precision with large values of P, which can't be easily recovered
                tot_mul = (tot_mul * ( (x - xj) // (xi - xj) )) % mod
            return tot_mul
        total = total + (yi * g(i, n)) % mod
    return total
