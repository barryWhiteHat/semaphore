# Copyright (c) 2018 HarryR.
# License: LGPL-3.0+


import json
from functools import reduce
from binascii import unhexlify
from collections import namedtuple

from py_ecc import bn128
from py_ecc.bn128 import pairing, G1, G2, FQ, FQ2, FQ12, neg, multiply, add


_VerifyingKeyStruct = namedtuple('_VerifyingKeyStruct',
    ('a', 'b', 'c', 'g', 'gb1', 'gb2', 'z', 'IC'))

_ProofStruct = namedtuple('_ProofStruct',
    ('a', 'a_p', 'b', 'b_p', 'c', 'c_p', 'k', 'h', 'input'))


def _bigint_bytes_to_int(x):
    """Convert big-endian bytes to integer"""
    return reduce(lambda o, b: (o << 8) + b if isinstance(b, int) else ord(b), [0] + list(x))


def _filter_int(x):
    """Decode an optionally hex-encoded big-endian string to a integer"""
    if isinstance(x, int):
        return x
    if x[:2] == '0x':
        x = x[2:]
    if len(x) % 2 > 0:
        x = '0' + x
    return _bigint_bytes_to_int(unhexlify(x))


def _load_g1_point(point):
    """Unserialize a G1 point, from Ethereum hex encoded 0x..."""
    if len(point) != 2:
        raise RuntimeError("Invalid G1 point - not 2 vals", point)

    out = tuple(FQ(_filter_int(_)) for _ in point)

    if not bn128.is_on_curve(out, bn128.b):
        raise ValueError("Invalid G1 point - not on curve", out)

    return out


def _load_g2_point(point):
    """Unserialize a G2 point, from Ethereum hex encoded 0x..."""
    x, y = point
    if len(x) != 2 or len(y) != 2:
        raise RuntimeError("Invalid G2 point x or y", point)

    # Points are provided as X.c1, X.c0, Y.c1, Y.c2
    # As in, each component is a 512 bit big-endian number split in two
    out = (FQ2([_filter_int(x[1]), _filter_int(x[0])]),
           FQ2([_filter_int(y[1]), _filter_int(y[0])]))

    if not bn128.is_on_curve(out, bn128.b2):
        raise ValueError("Invalid G2 point - not on curve:", out)

    # TODO: verify G2 point with another algorithm?
    #   neg(G2.one()) * p + p != G2.zero()
    return out


def pairingProd(*inputs):
    """
    The Ethereum pairing opcode works like:

       e(p1[0],p2[0]) * ... * e(p1[n],p2[n]) == 1

    See: EIP 212

    >>> assert True == pairingProd((G1, G2), (G1, neg(G2)))
    """
    product = FQ12.one()
    for p1, p2 in inputs:
        product *= pairing(p2, p1)
    return product == FQ12.one()


class Proof(_ProofStruct):
    """
    Object for zkSNARK proofs
    """

    def to_json(self):
        return json.dumps(self._asdict())

    @classmethod
    def from_dict(cls, in_data):
        """
        The G1 points in the proof JSON are affine X,Y,Z coordinates
        Because they're affine we can ignore the Z coordinate

        For G2 points on-chain, they're: X.c1, X.c0, Y.c1, Y.c0, Z.c1, Z.c0

        However, py_ecc is little endian, so it needs [X.c0, X.c1]
        """
        fields = []
        for name in cls._fields:
            val = in_data[name]
            if name == 'b':
                # See note above about endian conversion
                fields.append(_load_g2_point(val))
            elif name == 'input':
                fields.append([_filter_int(_) for _ in val])
            else:
                fields.append(_load_g1_point(val[:2]))
        return cls(*fields)


class VerifyingKey(_VerifyingKeyStruct):
    _g1_points = ['b', 'gb1']

    def to_json(self):
        # TODO: encode fields as hex
        return json.dumps(self._asdict())

    @classmethod
    def from_file(cls, filename):
        with open(filename, 'r') as handle:
            data = json.load(handle)
            return cls.from_dict(data)

    @classmethod
    def from_dict(cls, in_data):
        """Load verifying key from data dictionary, e.g. 'vk.json'"""
        fields = []
        for name in cls._fields:
            val = in_data[name]
            # Iterate in order, loading G1 or G2 points as necessary
            if name in cls._g1_points:
                fields.append(_load_g1_point(val))
            elif name == 'IC':
                fields.append(list([_load_g1_point(_) for _ in val]))
            else:
                fields.append(_load_g2_point(val))
        # Order is necessary to pass to constructor of self
        return cls(*fields)

    def verify(self, proof):
        """Verify if a proof is correct for the given inputs"""
        if not isinstance(proof, Proof):
            raise TypeError("Invalid proof type")

        # Compute the linear combination vk_x
        # vk_x = IC[0] + IC[1]^x[0] + ... + IC[n+1]^x[n]
        vk_x = self.IC[0]
        for i, x in enumerate(proof.input):
            IC_mul_x = multiply(self.IC[i + 1], x)
            vk_x = add(vk_x, IC_mul_x)

        # e(V_a,P_a) * e(G2,-P_a_p) == 1
        if not pairingProd((proof.a, self.a), (neg(proof.a_p), bn128.G2)):
            raise RuntimeError("Proof step 1 failed")

        # e(P_b,V_b) * e(G2,-P_b_p) == 1
        if not pairingProd((self.b, proof.b), (neg(proof.b_p), bn128.G2)):
            raise RuntimeError("Proof step 2 failed")

        # e(V_c,P_c) * e(G2,-P_c_p) == 1
        if not pairingProd((proof.c, self.c), (neg(proof.c_p), bn128.G2)):
            raise RuntimeError("Proof step 3 failed")

        # e(V_g,P_k) * e(V_gb2,-(vk_x+P_a+P_c)) * e(P_b,-P_gb1) == 1
        if not pairingProd(
            (proof.k, self.g),
            (neg(add(vk_x, add(proof.a, proof.c))), self.gb2),
            (neg(self.gb1), proof.b)):
            raise RuntimeError("Proof step 4 failed")

        # e(P_b, vk_x+P_a) * e(V_z,-P_h) * e(G2,-P_c) == 1
        if not pairingProd(
            (add(vk_x, proof.a), proof.b),
            (neg(proof.h), self.z),
            (neg(proof.c), bn128.G2)):
            raise RuntimeError("Proof step 5 failed")

        return True
