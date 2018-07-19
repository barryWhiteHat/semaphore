import sys
import json

from ..verifier import VerifyingKey


def fq_to_sol(o):
    return '"%s"' % (hex(o.n),)


def fq2_to_sol(o):
    # Fq2 is big-endian in EVM, so '[c1, c0]'
    return '[%s, %s]' % (fq_to_sol(o.coeffs[1]), fq_to_sol(o.coeffs[0]))


def g2_to_sol(o):
    return 'Pairing.G2Point(%s, %s)' % (fq2_to_sol(o[0]), fq2_to_sol(o[1]))


def g1_to_sol(o):
    return 'Pairing.G1Point(%s, %s)' % (fq_to_sol(o[0]), fq_to_sol(o[1]))


def main(vk_filename, name='vk', indent=''):
    """Outputs the solidity code necessary to instansiate a VerifyingKey variable"""
    with open(vk_filename, 'r') as handle:
        vk = VerifyingKey.from_dict(json.load(handle))
        g2 = {'A': 'a', 'C': 'c', 'gamma': 'g', 'gammaBeta2': 'gb2', 'Z': 'z'}
        g1 = {'B': 'b', 'gammaBeta1': 'gb1'}
        out = []
        for k, v in g2.items():
            x = getattr(vk, v)
            out.append("%s%s.%s = %s;" % (indent, name, k, g2_to_sol(x)))
        for k, v in g1.items():
            x = getattr(vk, v)
            out.append("%s%s.%s = %s;" % (indent, name, k, g1_to_sol(x)))
        for i, v in enumerate(vk.IC):
            out.append("%s%s.IC[%d] = %s;" % (indent, name, i, g1_to_sol(v)))
        return '\n'.join(out)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: ethsnarks.cli.vk2sol <vk.json> [var-name]")
        sys.exit(1)
    sys.exit(main(*sys.argv[1:]))
