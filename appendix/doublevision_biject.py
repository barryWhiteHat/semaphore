
from collections import defaultdict
from ethsnarks.longsight import powmod
from random import randint
import statistics

from math import gcd, sqrt

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



def analyze_sequences(sequences, p):
	# Identify differential probability that any `f(x1) - f(x2) = g`
	differential_g = randint(1, p-1)
	found_gs = 0
	for i, seq in enumerate(sequences[:-1]):
		seq2 = sequences[i+1]
		for j in range(0, p-1):
			if (seq[j] - seq2[j]) % p == differential_g:
				#print(i, j, seq[j], seq2[j], differential_g)
				found_gs += 1
	print("Found Gs = %.5f %.5f %.5f" % (found_gs/((p-1)*(p-1)), found_gs/(p-1), 1/p))

	# Then determine if there are any cycles
	all_subseqs_2 = []
	all_subseqs_3 = []
	all_subseqs_4 = []
	all_subseqs_5 = []
	all_subseqs_6 = []
	outs = defaultdict(int)
	for i, seq in enumerate(sequences):
		for j in range(0, len(seq)):
			#all_subseqs_6.append(tuple(seq[j % len(seq) - _] for _ in range(6,0,-1)))
			#all_subseqs_5.append(tuple(seq[j % len(seq) - _] for _ in range(5,0,-1)))
			all_subseqs_4.append(tuple(seq[j % len(seq) - _] for _ in range(4,0,-1)))
			all_subseqs_3.append(tuple(seq[j % len(seq) - _] for _ in range(3,0,-1)))
			all_subseqs_2.append(tuple(seq[j % len(seq) - _] for _ in range(2,0,-1)))
			outs[seq[j]] += 1

	print("Cycles 1", len(outs), statistics.variance(outs.values()))

	outs = defaultdict(int)
	for subseq in all_subseqs_2:
		outs[subseq] += 1
	print("Cycles 2", len(outs), statistics.variance(outs.values()))

	outs = defaultdict(int)
	for subseq in all_subseqs_3:
		outs[subseq] += 1
	print("Cycles 3", len(outs), statistics.variance(outs.values()))

	outs = defaultdict(int)
	for subseq in all_subseqs_4:
		outs[subseq] += 1
	print("Cycles 4", len(outs), statistics.variance(outs.values()))

	"""
	outs = defaultdict(int)
	for subseq in all_subseqs_5:
		outs[subseq] += 1
	print("Cycles 5", len(outs), statistics.variance(outs.values()))

	outs = defaultdict(int)
	for subseq in all_subseqs_6:
		outs[subseq] += 1
	print("Cycles 6", len(outs), statistics.variance(outs.values()))
	"""


def test_biject(p, polynomial):
	sequences = []
	C = [randint(1, p-1) for _ in range(0, 3)]
	found_ms = []
	found_ks = []
	found_0s = []
	for m in range(0, p-1):	# or int(sqrt(p)) for smaller sample
		found = list()
		found_k = 0
		found_m = 0
		found_0 = 0
		for k in range(0, p-1):
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
			found.append(x)
		if len(found) != p-1:
			raise RuntimeError("Not a bijection! %d %d %d %d" % (m, k, p, len(found)))
		if found in sequences:
			raise RuntimeError("Duplicate sequence!")
		sequences.append(tuple(found))
		found_0s.append(found_0)
		found_ms.append(found_m)
		found_ks.append(found_k)

	analyze_sequences(sequences, p)

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
			print("")
		else:
			raise RuntimeError("No bijection for %d" % (p,))

for p in PRIMES.split():
	p = int(p)
	eval_prime(p)

with open('first-mil-primes.txt', 'r') as handle:
	for p in handle:
		p = int(p.strip())
		eval_prime(p)
