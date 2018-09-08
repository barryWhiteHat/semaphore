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

    r = int(log2(p)/log2(3)) + 1 = 161
    r = math.ceil(log(p, 3)) + 1 = 161
"""

from __future__ import print_function

import math
import struct
from random import randint

from hashlib import sha256
from py_ecc.bn128 import curve_order

from .r1cs import r1cs_constraint


def random_element():
    return randint(1, curve_order-1)


def _make_constants(name, n, e):
    """
    Generate round constants for a Longsight/MiMC family algorithm
    """
    output = []
    name = "%s%dp%d" % (name, n, e)
    for i in range(0, n):
        const_bytes = name.encode('ascii') + struct.pack('<L', i)
        output.append(int.from_bytes(sha256(const_bytes).digest(), 'little') % curve_order)
    return name, output


def make_constants_L(name, n, e):
    name, C = _make_constants(name, n, e)
    C[0] = 0
    C[-1] = 0
    return name, C


def make_constants_F(name, n, e):
    # XXX: Previous version didn't zero out first and last round constants
    return _make_constants(name, n, e)


def _make_constants_cxx(name, constants_list):
    """
    Convert constants into a C++ function which populates a vector with them
    """
    output = "template<typename FieldT>\nvoid %s_constants_fill( std::vector<FieldT> &round_constants )\n{\n" % (name,)
    output += "\tround_constants.resize(%d);\n" % (len(constants_list),)
    for i, constant in enumerate(constants_list):
        output += "\tround_constants[%d] = FieldT(\"%d\");\n" % (i, constant)
    output += "}\n"
    output += """
template<typename FieldT>
const std::vector<FieldT> %s_constants_assign( )
{
    std::vector<FieldT> round_constants;

    %s_constants_fill<FieldT>(round_constants);

    return round_constants;
}""" % (name, name,)
    return output


def make_constants_cxx_F(name, n, e):
    return _make_constants_cxx(*make_constants_F(name, n, e))


def make_constants_cxx_L(name, n, e):
    return _make_constants_cxx(*make_constants_L(name, n, e))


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


def LongsightL(x, k, C, R, e, p):
    """
    @param x input
    @param k key
    @param C constants
    @param R number of rounds
    @param e exponent
    @param p field prime
    """
    assert math.gcd(p-1, e) == 1       # XXX: is a bijection required?
    assert len(C) == R

    assert x > 0 and x < (p-1)
    if k != 0:
        assert k > 0 and k < (p-1)

    x_i = x

    for C_i in C:
        t = (x_i + k + C_i) % p
        sq5 = powmod(t, e, p)
        x_i = (x_i + sq5) % p

    return x_i


def MiyaguchiPreneel_OWF(M, IV, fn, p):
    """
    The Miyaguchi–Preneel single-block-length one-way compression
    function is an extended variant of Matyas–Meyer–Oseas. It was
    independently proposed by Shoji Miyaguchi and Bart Preneel.

    H_i = E_{H_{i-1}}(m_i) + {H_{i-1}} + m_i

    or..

                 m_i
                  |
                  |----,
                  v    |
    H_{i-1}----->[E]   |
             |    |    |
             `-->(+)<--'
                  |
                  v
               m_{i+1}

    @param M list of inputs
    @param IV initial key
    @param C constants
    @param fn Keyed hash function or block cipher
    """
    assert isinstance(M, (list, tuple))
    assert len(M) > 1
    k_i = IV
    H_i = 0
    for m_i in M:
        k_i = fn(m_i, k_i)
        H_i = (H_i + m_i + k_i) % p
        k_i = H_i
    return H_i


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
    #assert R >= 2 * (int(math.log(p, 3)) + 1)
    #assert math.gcd(p-1, e) == 1       # XXX: is a bijection required?
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


def LongsightL12p5(x, k):
    p = curve_order
    e = 5
    R = 12
    _, C = make_constants_L("LongsightL", R, e)
    C[0] = 0
    C[-1] = 0
    return LongsightL(x, k, C, R, e, p)


def LongsightL12p5_MP(M, IV):
    return MiyaguchiPreneel_OWF(M, IV, LongsightL12p5, curve_order)


def LongsightF12p5(x_L, x_R):
    p = curve_order
    e = 5
    R = 12
    _, C = make_constants_F("LongsightF", R, e)
    return LongsightF(x_L, x_R, C, R, e, p)


def LongsightF322p5(x_L, x_R):
    p = curve_order
    e = 5
    R = 322
    _, C = make_constants_F("LongsightF", R, e)
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
    print(make_constants_cxx_L("LongsightL", 12, 5))
