import sys
import json

from ..verifier import Proof

from .utils import g2_to_sol, g1_to_sol, fq_to_sol


def main(vk_filename, name='_getStaticProof'):
    """Outputs the solidity code necessary to instansiate a Proof variable"""
    with open(vk_filename, 'r') as handle:
        proof = Proof.from_dict(json.load(handle))
        g2 = {'B': 'b'}
        g1 = {'A': 'a', 'A_p': 'a_p', 'B_p': 'b_p', 'C': 'c', 'C_p': 'c_p', 'K': 'k', 'H': 'h'}
        indent = "\t\t";
        varname = "proof";

        out = [
            "\tfunction %s (Verifier.Proof memory %s)" % (name, varname),
            "\t\tinternal pure",
            "\t{",
        ]

        for k, v in g2.items():
            x = getattr(proof, v)
            out.append("%s%s.%s = %s;" % (indent, varname, k, g2_to_sol(x)))

        for k, v in g1.items():
            x = getattr(proof, v)
            out.append("%s%s.%s = %s;" % (indent, varname, k, g1_to_sol(x)))

        out.append("%s%s.input = new uint256[](%d);" % (indent, varname, len(proof.input)))
        for i, v in enumerate(proof.input):
            out.append("%s%s.input[%d] = %s;" % (indent, varname, i, hex(v)))

        out.append("\t}");
        print('\n'.join(out))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: ethsnarks.cli.proof2sol <proof.json> [func-name]")
        print("Outputs Solidity code, depending on Verifier.sol, which can be included in your code")
        sys.exit(1)
    sys.exit(main(*sys.argv[1:]))
