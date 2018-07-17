from collections import namedtuple

from py_ecc.bn128 import pairing, G1, G2, FQ12, neg


VerifyingKey = namedtuple('VerifyingKey', ('A', 'B', 'C', 'gamma', 'gammaBeta1', 'gammaBeta2', 'Z', 'IC'))
Proof = namedtuple('Proof', ('A', 'A_p', 'B', 'B_p', 'C', 'C_p', 'K', 'H'))


def pairingProd(*inputs):
    """
    The ethereum opcode works like:

       e(p1[0],p2[0]) * ... * e(p1[n],p2[n]) == 1

    >>> assert True == pairingProd((G1, G2), (G1, neg(G2)))
    """
    product = FQ12.one()
    for p1, p2 in inputs:
        product *= pairing(p2, p1)
    return product == FQ12.one()


def verify_py_ecc(vk, proof, inputs):
    # Compute the linear combination vk_x
    vk_x = [0, 0]
    for i, x in enumerate(inputs):
        vk_x = add(vk_x, multiply(vk.IC[i + 1], x))
    vk_x = add(vk_x, vk.IC[0])

    # pairingProd = 

    assert pairingProd((proof.A, vk.A), (neg(proof.A_p), G2))
    assert pairingProd((vk.B, proof.B), (neg(proof.B_p), G2))
    assert pairingProd((proof.C, vk.C), (neg(proof.C_p), G2))

    assert pairingProd(
        (proof.K, vk.gamma),
        (neg(add(vk_x, add(proof.A, proof.C))), vk.gammaBeta2),
        (neg(vk.gammaBeta1), proof.B))

    assert pairingProd(
        (add(vk_x, proof.A), proof.B),
        (neg(proof.H), vk.Z),
        (neg(proof.C), G2))
