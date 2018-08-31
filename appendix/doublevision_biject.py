"""
Verifies that various polynomials are bijections across prime numbers
with different qualities.

This aims to prove, intuitively, that the exponent (x^5) used in the
LongsightF polynomial is a permutation.
"""

from ethsnarks.longsight import powmod
from random import randint
import statistics

from math import gcd

PRIMES = """
2 3 5 7 11 13 17 19 23 29 31 37 41 43 47 53 59 61 67 71 73 79 83
89 97 101 103 107 109 113 127 131 137 139 149 151 157 163 167
173 179 181 191 193 197 199 211 223 227 229 233 239 241 251 257
997 1009 1013 1019 1021 1031 1033 1039 1049 1051 1061 1063 1069
1087 1091 1093 1097 1103 1109 1117 1123 1129 1151 1153 1163 1171
8059 8069 8081 8087 8089 8093 8101 8111 8117 8123 8147 8161 8167
28979 29009 29017 29021 29023 29027 29033 29059 29063 29077
46867 46877 46889 46901 46919 46933 46957 46993 46997 47017
60077 60083 60089 60091 60101 60103 60107 60127 60133 60139
78941 78977 78979 78989 79031 79039 79043 79063 79087 79103
104651 104659 104677 104681 104683 104693 104701 104707 104711
"""

def test_biject(p, polynomial):
	sequences = []
	C = [randint(1, p-1) for _ in range(0, 5)]
	found_ms = []
	found_ks = []
	found_0s = []
	for m in range(1, p-1):
		found = set()
		found_k = 0
		found_m = 0
		found_0 = 0
		for k in range(1, p-1):
			x = polynomial(m, k, p, C)
			assert x >= 0
			assert x < p
			if x in found:
				raise RuntimeError("Error")
			if x == k:
				found_k += 1
			if x == m:
				found_m += 1
			if x == 0:
				found_0 += 1
			found.add(x)
		if len(found) != p-2:
			raise RuntimeError("Not a bijection! %d %d %d" % (i, j, p))
		if found in sequences:
			raise RuntimeError("Duplicate sequence!")
		sequences.append(tuple(sorted(found)))
		found_0s.append(found_0)
		found_ms.append(found_m)
		found_ks.append(found_k)
	print("stddev", "m=",statistics.stdev(found_ms), "k=",statistics.stdev(found_ks), "0=", statistics.stdev(found_0s))
	print("variance", "m=",statistics.variance(found_ms), "k=",statistics.variance(found_ks), "0=", statistics.variance(found_0s))
	return True


def DoublevisionH_e(m, k, p, C):
	y = (m + k) % p
	for C_i in C:
		m = powmod((m + C_i) % p, 5, p)
		k = powmod((k + y) % p, 5, p)
		y = (m + k) % p
	return y


polynomials = [
	("DoublevisionH_e", DoublevisionH_e),
]

def eval_prime(p):
	if gcd(p-1, 2) != 2:
		return
	if gcd(p-1, 3) != 3:
		return
	if gcd(p-1, 4) != 4:
		return
	if gcd(p-1, 5) != 1:
		return
	#print("Found", p)	
	for name, poly in polynomials:
		if test_biject(p, poly):
			print(name, p)
		else:
			raise RuntimeError("No bijection for %d" % (p,))

for p in PRIMES.split():
	p = int(p)
	eval_prime(p)

with open('first-mil-primes.txt', 'r') as handle:
	for p in handle:
		p = int(p.strip())
		eval_prime(p)
