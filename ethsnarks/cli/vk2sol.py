import sys
import json

from ..verifier import VerifyingKey

from .utils import g2_to_sol, g1_to_sol


def main(vk_filename, name='_getVerifyingKey'):
    """Outputs the solidity code necessary to instansiate a VerifyingKey variable"""
    with open(vk_filename, 'r') as handle:
        vk = VerifyingKey.from_dict(json.load(handle))
        g2 = {'A': 'a', 'C': 'c', 'gamma': 'g', 'gammaBeta2': 'gb2', 'Z': 'z'}
        g1 = {'B': 'b', 'gammaBeta1': 'gb1'}
        indent = "\t\t";
        varname = "vk";
        out = [
            "\tfunction %s ()" % (name,),
            "\t\tinternal pure returns (Verifier.VerifyingKey memory)",
            "\t{",
            "\t\tVerifier.VerifyingKey memory %s;\n" % (varname,)
        ]
        for k, v in g2.items():
            x = getattr(vk, v)
            out.append("%s%s.%s = %s;" % (indent, varname, k, g2_to_sol(x)))
        for k, v in g1.items():
            x = getattr(vk, v)
            out.append("%s%s.%s = %s;" % (indent, varname, k, g1_to_sol(x)))
        out.append("%s%s.IC = new Pairing.G1Point[](%d);" % (indent, varname, len(vk.IC)))
        for i, v in enumerate(vk.IC):
            out.append("%s%s.IC[%d] = %s;" % (indent, varname, i, g1_to_sol(v)))
        out.append("\t}");
        print('\n'.join(out))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: ethsnarks.cli.vk2sol <vk.json> [func-name]")
        print("Outputs Solidity code, depending on Verifier.sol, which can be included in your code")
        sys.exit(1)
    sys.exit(main(*sys.argv[1:]))
