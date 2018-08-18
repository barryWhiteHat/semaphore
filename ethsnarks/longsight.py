# Copyright (c) 2018 HarryR
# License: LGPL-3.0+

"""
https://eprint.iacr.org/2016/492.pdf
https://eprint.iacr.org/2016/542.pdf
https://github.com/zcash/zcash/issues/2233
https://keccak.team/files/SpongeIndifferentiability.pdf

Where the field F_p is prime, it needs to be assured that
the cubing in the round function creates a permutation.
For this is, it is sufficient to require gcd(n, p-1) = 1

p = curve_order = 21888242871839275222246405745257275088548364400416034343698204186575808495617
e = 5
gcd(e, p-1) = 1

The number of rounds for constructing the keyed permutation is

    r = int(log(p)/log2(e)) = 75
    r = math.ceil(log(p, e)) = 110
"""

from __future__ import print_function

import math
import struct

from hashlib import sha256
from py_ecc.bn128 import curve_order

from .r1cs import r1cs_constraint


def make_constants(name, n, e):
    """
    Generate round constants for a Longsight/MiMC family algorithm
    """
    output = []
    name = "%s%dp%d" % (name, n, e)
    for i in range(0, n):
        const_bytes = name.encode('ascii') + struct.pack('<L', i)
        output.append(int.from_bytes(sha256(const_bytes).digest(), 'little') % curve_order)
    return name, output


def make_constants_cxx(name, n, e):
    """
    Convert constants into a C++ function which populates a vector with them
    """
    name, constants_list = make_constants(name, n, e)
    output = "template<typename FieldT>\nvoid %s_constants( std::vector<FieldT> &round_constants )\n{\n" % (name,)
    output += "\tround_constants.resize(%d);\n" % (n,)
    for i, constant in enumerate(constants_list):
        output += "\tround_constants[%d] = FieldT(\"%d\");\n" % (i, constant)
    output += "}\n"
    return output


def powmod(a, b, n):
    """Modulo exponentiation"""
    c = 0
    f = 1
    k = int(math.log(b, 2))
    while k >= 0:
        c *= 2
        f = (f*f)%n
        if b & (1 << k):
            c += 1
            f = (f*a) % n
        k -= 1
    return f


def LongsightL(x, C, R, e, p, k=0):
    """
    @param x input
    @param C constants
    @param R number of rounds
    @param e exponent
    @param p field prime
    @param k optional key
    """
    assert math.gcd(p-1, e) == 1
    assert R >= math.ceil(math.log(p) / math.log2(e))
    assert len(C) == R

    assert x > 0 and x < (p-1)
    if k != 0:
        assert k > 0 and k < (p-1)

    x_i = x

    for i in range(0, R-1):
        j = powmod(x_i + k + C[i], e, p)
        x_i = (x_i + j) % p

    return x_i


def LongsightF(x_L, x_R, C, R, e, p, k=0):
    """
    As per MiMC-2n/n (Feistel)

    By using the same non-linear permutation in a Feistel
    network, we can process larger blocks at the cost of 
    increasing the number of rounds by a factor of two.

    The round function of MiMC-2n/n is defined as follows:

        x_L || x_R <- x_R + (x_L + k + c_i)^e || x_L

    @param x_L input 0
    @param x_R input 1
    @param C constants
    @param R number of rounds
    @param e exponent
    @param p field prime
    @param k optional key
    """
    #assert R >= 2 * math.ceil(math.log(p) / math.log2(e))
    assert math.gcd(p-1, e) == 1
    assert len(C) == R

    assert x_L > 0 and x_L < (p-1)
    assert x_R > 0 and x_R < (p-1)
    if k != 0:
        assert k > 0 and k < (p-1)

    # Calculate rounds
    for i in range(0, R):
        j = powmod(x_L + k + C[i], e, p)
        x_L, x_R = (x_R + j) % p, x_L

    return x_L


def LongsightF5p5(x_L, x_R):
    p = curve_order
    e = 5
    R = 5
    _, C = make_constants("LongsightF", R, e)
    return LongsightF(x_L, x_R, C, R, e, p)


def LongsightF152p5(x_L, x_R):
    p = curve_order
    e = 5
    R = 2 * math.ceil(math.log(p) / math.log2(e))
    assert R == 152
    _, C = make_constants("LongsightF", R, e)
    return LongsightF(x_L, x_R, C, R, e, p)


"""
From: https://keccak.team/files/SpongeIndifferentiability.pdf

message `x` split into `r` bit blocks
r = 253 (the bitrate)
p = sequence of `r` bit blocks
|p| = number of blocks
n = output length (bits)
c = capacity (bits)

Section 5:

The security parameter is the capacity `c` and not the output 
length of the hash function. The indifferentiability bounds in
terms of the capacity `c` permit to express up to which output length
`n` such a hash function may offer the expected resistence. For example,
it offers collision resistance (as a truncated random oracle would) for
any output length smaller than the capacity, and (2nd) preimage resistance
for any output length smaller than half the capacity.

In other words, when for instance `c = 512`, a random sponge offers the same
resistance as a random oracle but with a maximum of `2^256` in complexity.


def sponge(p, n, r, F):
    z = []
    s_a, s_c = 0, 0
    for i in range(0, len(p)):
        s_a, s_c = F(s_a + p[i], s_c)
    for j in range(0, (n/r) - 1):
        z.append(s_a)
        s_a, s_c = F(s_a, s_c)
    # TODO: Discard the last `r[n/r] - n` bits
    return z
"""

if __name__ == "__main__":
    #print(LongsightF152p5(1, 1))
    print(make_constants_cxx("LongsightF", 5, 5))
