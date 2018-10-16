pragma solidity 0.4.24;
pragma experimental ABIEncoderV2;


import "./Miximus.sol";
import "./Verifier.sol";


// Please note, it saves a lot of gas to use the `vk2sol`
// utility to generate Solidity code, hard-coding the
// verifying key avoids the cost of loading from storage.

contract TestableMiximus is Miximus
{
    Verifier.VerifyingKey internal m_vk;

    constructor( uint256[2] alpha, uint256[2][2] beta, uint256[2][2] gamma, uint256[2][2] delta, uint256[] gammaABC )
        public
    {
        m_vk.alpha = Pairing.G1Point(alpha[0], alpha[1]);
        m_vk.beta = Pairing.G2Point(beta[0], beta[1]);
        m_vk.gamma = Pairing.G2Point(gamma[0], beta[1]);
        m_vk.delta = Pairing.G2Point(delta[0], delta[1]);

        uint n_abc = gammaABC.length / 2;
        for (uint i = 0; i < n_abc; i += 2)
        {
            m_vk.gammaABC.push( Pairing.G1Point(gammaABC[i], gammaABC[i+1]) );
        }
    }

    function NegateY( uint256 Y )
        internal pure returns (uint256)
    {
        uint q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        return q - (Y % q);
    }

    /*
    * This implements the Solidity equivalent of the following Python code:

        from py_ecc.bn128 import *

        data = # ... arguments to function [in_vk, vk_gammaABC, in_proof, proof_inputs]

        vk = [int(_, 16) for _ in data[0]]
        ic = [FQ(int(_, 16)) for _ in data[1]]
        it = iter(ic)
        ic = [(_, next(it)) for _ in it]
        proof = [int(_, 16) for _ in data[2]]
        inputs = [int(_, 16) for _ in data[3]]

        vk_alpha = [FQ(_) for _ in vk[:2]]
        vk_beta = (FQ2(vk[2:4]), FQ2(vk[4:6]))
        vk_gamma = (FQ2(vk[6:8]), FQ2(vk[8:10]))
        vk_delta = (FQ2(vk[10:12]), FQ2(vk[12:14]))

        proof_A = [FQ(_) for _ in proof[:2]]
        proof_B = (FQ2(proof[2:4]), FQ2(proof[4:-2]))
        proof_C = [FQ(_) for _ in proof[-2:]]

        vk_x = ic[0]
        for i, s in enumerate(inputs):
            vk_x = add(vk_x, multiply(ic[i + 1], s))

        check_1 = pairing(proof_B, proof_A)
        check_2 = pairing(vk_beta, neg(vk_alpha))
        check_3 = pairing(vk_gamma, neg(vk_x))
        check_4 = pairing(vk_delta, neg(proof_C))

        ok = check_1 * check_2 * check_3 * check_4
        assert ok == FQ12.one()
    */
    function TestVerify ( uint256[14] in_vk, uint256[] vk_gammaABC, uint256[8] in_proof, uint256[] proof_inputs )
        public view returns (bool)
    {
        require( ((vk_gammaABC.length / 2) - 1) == proof_inputs.length );

        // Compute the linear combination vk_x
        uint256[3] memory mul_input;
        uint256[4] memory add_input;
        bool success;
        uint m = 2;

        // First two fields are used as the sum
        add_input[0] = vk_gammaABC[0];
        add_input[1] = vk_gammaABC[1];

        // Performs a sum of gammaABC[0] + sum[ gammaABC[i+1]^proof_inputs[i] ]
        for (uint i = 0; i < proof_inputs.length; i++) {
            mul_input[0] = vk_gammaABC[m++];
            mul_input[1] = vk_gammaABC[m++];
            mul_input[2] = proof_inputs[i];

            assembly {
                // ECMUL, output to last 2 elements of `add_input`
                success := staticcall(sub(gas, 2000), 7, mul_input, 0x80, add(add_input, 0x40), 0x60)
            }
            require( success );

            assembly {
                // ECADD
                success := staticcall(sub(gas, 2000), 6, add_input, 0xc0, add_input, 0x60)
            }
            require( success );
        }

        uint[24] memory input = [
            // (proof.A, proof.B)
            in_proof[0], in_proof[1],                           // proof.A   (G1)
            in_proof[2], in_proof[3], in_proof[4], in_proof[5], // proof.B   (G2)

            // (-vk.alpha, vk.beta)
            in_vk[0], NegateY(in_vk[1]),                        // -vk.alpha (G1)
            in_vk[2], in_vk[3], in_vk[4], in_vk[5],             // vk.beta   (G2)

            // (-vk_x, vk.gamma)
            add_input[0], NegateY(add_input[1]),                // -vk_x     (G1)
            in_vk[6], in_vk[7], in_vk[8], in_vk[9],             // vk.gamma  (G2)

            // (-proof.C, vk.delta)
            in_proof[6], NegateY(in_proof[7]),                  // -proof.C  (G1)
            in_vk[10], in_vk[11], in_vk[12], in_vk[13]          // vk.delta  (G2)
        ];

        uint[1] memory out;
        assembly {
            success := staticcall(sub(gas, 2000), 8, input, 768, out, 0x20)
        }
        require(success);
        return out[0] != 0;
    }

    /*
    function GetVerifyingKey ()
        internal view returns (Verifier.VerifyingKey memory)
    {       
        return m_vk;
    }
    */

    function GetVerifyingKey (Verifier.VerifyingKey memory vk)
        internal view
    {
        vk.beta = Pairing.G2Point([0x23df5e88ef8c695a936273071fc2e9a5879000d8f2913c8005671f61a4a70450, 0x5bae69b8321c67e66a879485bd5aac2dd12ceeafd7f00f66b26321fbdeef2f], [0x1ca5a54c39f533a764a6aa55f419f7096154efc87f5c1ffb5d6f42635de7b377, 0x1642c8f546b5c22aab6c845becf1fbb51324de210f03dd9b2168e54e79d2ac98]);
        vk.gamma = Pairing.G2Point([0x283cbe4ec00a7643c188241d4fd9f355a5ef5152da1e9c3c9d63944497f6bd48, 0x17f03d61d33e192a13685aa92f16ae4e91e9e0161668dd851ebbdc93407ac45e], [0x2e852427ff695a858b4c3b3f92a37902c289d2a349115433202f9051469f24b, 0xf89dcea40987650ab1d6ef61b56e20eba020ee242b37ca410ef0707adf28491]);
        vk.delta = Pairing.G2Point([0x6df26e0f964cca91b63ff08fc3ff88afbf7987112a7a744b5212414de1d19c0, 0x224dd01e810047dd4c2cd6d9e61971d428d8be3fd4f905f773c1b5bf65ad39f8], [0x1d6d2db772e306fd6c4c7ff6b6a600d4858ef3ce916bac197f771e2e2df1fdea, 0x20b6776ea70b71d14608bac3aa8138bb929b33eec13f7b2fb14c98a08f5ee7b1]);
        vk.alpha = Pairing.G1Point(0x1ce2c55eb08dfa89aa5a6d4c6e154dc061b7e8957d8fe85a5f70844836bf8894, 0x1f1f893a9c27e8291657d34201af9b067d51d1a8ef3db7c22187395513c8178);
        vk.gammaABC = new Pairing.G1Point[](4);
        vk.gammaABC[0] = Pairing.G1Point(0x2a35065121197a468d9df1f24d9dd651ba24eadcc6751af5dae267072530a8d8, 0x515b91005d65dcc5bbc0d565724ad9cd0319c455555d45c74a3d23bee6e0848);
        vk.gammaABC[1] = Pairing.G1Point(0x2d8b52c31635db7c7121be2deee1f5ed8f7a138d55f311b84cc86159694973bb, 0x103f5af198ae40847d0b49d229116a26eee0e381050fee767cd6672f672adcd2);
        vk.gammaABC[2] = Pairing.G1Point(0x13fba7f73646725d4e8e68795c453b2661db11339aabfa09a3e3fbee34d72ebe, 0x49da6ff964ac686ca98e31b8c17539c8d55438d12fdde26fe6aac5a729d239a);
        vk.gammaABC[3] = Pairing.G1Point(0x2059f55d13bf8182e68e3d173584cebbb6dbcc4e9b8374f68473b81709c0b88b, 0x2647c112c905d12c414a7c5d7bb64b2dc42df9a61d9a74ecc44f140f461d65eb);
    }
}
