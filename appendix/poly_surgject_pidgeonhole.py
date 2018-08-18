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

from collections import defaultdict
from math import gcd

from ethsnarks.mimc import powmod


def test_pigeonhole(p, polynomial):
	found = defaultdict(int)
	for a in range(1, p-1):
		for b in range(1, p-1):
			m = polynomial(a, b, p)
			found[m] += 1
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
	poly = lambda a, b, p: (a + b) % p
	result = test_pigeonhole(p, poly)
	print(p, result, p/result, result/p)


with open('first-mil-primes.txt', 'r') as handle:
	for p in handle:
		p = int(p.strip())
		eval_prime(p)
