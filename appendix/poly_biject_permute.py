"""
Verifies that various polynomials are bijections across prime numbers
with different qualities.

This aims to prove, intuitively, that the exponent (x^5) used in the
LongsightF polynomial is a permutation.
"""

from ethsnarks.longsight import powmod
from random import randint

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
	found = set()
	for n in range(1, p-1):
		m = polynomial(n, p)
		if m in found:
			return False
		found.add(m)
	return len(found) == p-2


C = []


def DoublevisionL(n, p):
	for i in range(0, 10):
		n = powmod((n + C[(i * 2)]) % p, 5, p) % p
	return n


def DoublevisionM(n, p):
	a = n
	b = n
	for i in range(0, 4):
		y = (a + b) % p
		a = powmod((a + C[(i * 2)]) % p, 5, p)
		b = powmod((b + C[(i * 2) + 1]) % p, 5, p) + y % p
	return a


def DoublevisionH_e(k, p, r=5):
	m = p-r
	y = 0
	for i in range(0, r):
		y = (m + k) % p
		m = powmod((m + C[i]) % p, 5, p)
		k = powmod((k + y) % p, 5, p)
	return y


def DoublevisionH_ex(k, p, r=5):
	m = k
	y = 0
	for i in range(0, r):
		y = (m * k) % p
		m = powmod((m + C[i]) % p, 5, p)
		k = powmod((k + y) % p, 5, p) * m
	return y


def DoublevisionH_xx(k, p, r=5):
	m = r
	y = 0
	for i in range(0, r):
		y = (m + k) % p
		m = powmod((m + C[i]) % p, 5, p)
		k = (powmod((k + y) % p, 5, p)) % p
	return y



def DoublevisionH_xxy(k, p, r=5):
	m = r
	y = 0
	for i in range(0, r):
		m = powmod((m + C[(2*i)]) % p, 5, p)
		k = powmod((k + C[(2*i)+1]) % p, 5, p) + m
	y = (m * k) % p
	return y



def DoublevisionH_j(m, p, r, k):
	y = 0
	for i in range(0, r):
		y = (m * k) % p
		m = powmod(m + C[i * 2], 5, p)
		k = (powmod((k + C[(i * 2) + 1]) % p, 5, p) * m) % p
	return y


def DoublevisionH_x(m, p, r=4):
	k = r
	y = 0
	for i in range(0, r):
		y = (m * k) % p
		m = powmod(m + y, 5, p) % p 
		k = powmod(k + C[i], 5, p) % p
	return y


def DoublevisionH_j_r4_k12(m, p):
	return DoublevisionH_j(2, p, 10, m)


polynomials = [
	#('x^2', lambda n, p: powmod(n, 2, p)),
	#('(x^2)-x', lambda n, p: powmod(n, 2, p) - n),
	#('(x^2)+x', lambda n, p: powmod(n, 2, p) + n),
	#('(x^2)+1', lambda n, p: powmod(n, 2, p) + 1),
	#('x^3', lambda n, p: powmod(n, 3, p)),
	#('(x^3)-x', lambda n, p: powmod(n, 3, p) - n),
	#('(x^3)+x', lambda n, p: powmod(n, 3, p) + n),
	#('(x^3)+1', lambda n, p: powmod(n, 3, p) + 1),
	#('(x^3)+2', lambda n, p: powmod(n, 3, p) + 2),
	#('(x^3)-1', lambda n, p: powmod(n, 3, p) - 1),
	#('x^4', lambda n, p: powmod(n, 4, p)),
	#('x^5', lambda n, p: powmod(n, 5, p)),
	#('(2*(x^2))+x', lambda n, p: (2 * powmod(n, 2, p)) + n)
	#("DoublevisionH_j", DoublevisionH_j_r4_k12),
	#("DoublevisionL", DoublevisionL),
	#("DoublevisionM", DoublevisionM),
	#("DoublevisionH_xx", DoublevisionH_xx),
	("DoublevisionH_e", DoublevisionH_e),
	#("DoublevisionH_e", DoublevisionH_e),
]

def eval_prime(p):
	global C
	if gcd(p-1, 2) != 2:
		return
	if gcd(p-1, 3) != 3:
		return
	if gcd(p-1, 4) != 4:
		return
	if gcd(p-1, 5) != 1:
		return
	C = [randint(1, p-1) for _ in range(0, 50)]
	#print("Found", p)	
	for name, poly in polynomials:
		if test_biject(p, poly):
			print(name, p)
		else:
			print("No bijection for", p)

for p in PRIMES.split():
	p = int(p)
	eval_prime(p)

with open('first-mil-primes.txt', 'r') as handle:
	for p in handle:
		p = int(p.strip())
		eval_prime(p)
