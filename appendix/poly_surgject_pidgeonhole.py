"""
This aims to prove, intuitively, that there is a surjective 
hash function which, when operating on primes with the same properties
as the altBN256 curve order, adhere to the pidgeon-hole principle:

	Given two positive integers `n` and `m`, if `n` items are put
	into `m` holes then at least one hole must contain more than or
	equal to `n/m` items.

For example, if `H(a,b) -> Z_q`, without control over either `a` or `b`,
then there is a `1/(2^log2(|Z_q|))` probability of overlap. e.g. if any
pigeonhole contains more than 3 items then there's a problem, if every
hole contains 2 items then it's 'perfect', and it should be impossible
for every hole to contain only 1 item as that would be a bijection.
"""

import statistics
from collections import defaultdict
from math import gcd
from random import randint

from ethsnarks.longsight import powmod, LongsightF, make_constants


def LongsightF4p3(x_L, x_R, p, C=None):
    e = 3
    R = 4
    _, C = make_constants("LongsightF", R, e)
    return LongsightF(x_L, x_R, C, R, e, p)

def LongsightF6p5(x_L, x_R, p, C=None):
    e = 5
    R = 6
    _, C = make_constants("LongsightF", R, e)
    return LongsightF(x_L, x_R, C, R, e, p)


def DoublevisionH_e(m, k, p, C, r=4):
	y = (m + k) % p
	for i in range(0, r):
		m = powmod((m + C[i]) % p, 5, p)
		k = powmod((k + y) % p, 5, p)
		y = (m + k) % p
	return y


def DoublevisionH_xxy(k, m, p, C, r=5):
	y = 0
	for i in range(0, r):
		m = powmod((m + C[(2*i)]) % p, 5, p)
		k = powmod((k + C[(2*i)+1]) % p, 5, p) + m
	y = (m * k) % p
	return y


def DoublevisionH_i(m, k, p, C, r=4):
	y = 0
	e = 5
	for i in range(0, r):
		y = (m + k) % p
		m = (powmod((m + C[(2*i)]) % p, e, p) + y) % p
		k = (powmod((k + C[(2*i)+1]) % p, e, p) + y) % p
	return y


def DoublevisionM(x_L, x_R, p, C, r=4):
	a = x_L
	b = x_R
	for i in range(0, r):
		y = (a + b) % p
		a = powmod((a + C[(i * 2)]) % p, 5, p)
		b = powmod((b + C[(i * 2) + 1]) % p, 5, p) + y % p
	return a


def DoublevisionH_x(m, k, p, C, r=4):
	y = 0
	for i in range(0, r):
		y = (m * k) % p
		m = powmod(m + y, 5, p) % p 
		k = powmod(k + C[i], 5, p) % p
	return y


def test_pigeonhole(p, polynomial, C):
	found = defaultdict(int)
	for a in range(1, p-1):
		for b in range(1, p-1):
			m = polynomial(a, b, p, C)
			found[m] += 1
	print("stdev:", statistics.stdev(found.values()))
	#print("median:", statistics.median(found.values()))
	#print("mean:", statistics.mean(found.values()))
	#print("harmonic_mean:", statistics.harmonic_mean(found.values()))
	print("variance:", statistics.variance(found.values()))
	#print(found)
	return sum(found.values())


def eval_prime(p):
	if gcd(p-1, 2) != 2:
		return
	if gcd(p-1, 3) != 3:
		return
	if gcd(p-1, 4) != 4:
		return
	if gcd(p-1, 5) != 1:
		return

	#poly = lambda a, b, p: (powmod(a, 2, p) + b) % p
	#poly = lambda a, b, p: (a + b) % p
	C = [randint(1, p-1) for _ in range(0, 20)]
	poly = DoublevisionH_e
	result = test_pigeonhole(p, poly, C)
	print(p, result, p/result, result/p)
	print("")


with open('first-mil-primes.txt', 'r') as handle:
	for p in handle:
		p = int(p.strip())
		eval_prime(p)
