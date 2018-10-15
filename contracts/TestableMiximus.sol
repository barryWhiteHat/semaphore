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

    event Derp( Verifier.VerifyingKey k );

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

    /*
    * vk 
    *   2 alpha
    *   4 beta
    *   4 gamma
    *   4 delta
    *   n*2 gammaABC
    * - 14 + (2*n)
    *
    * proof
    *   2 A
    *   4 B
    *   2 C
    *   (n-1) * inputs
    * - 8 + (n-1)
    */
    function TestVerify ( uint256[14] in_vk, uint256[] vk_gammaABC, uint256[8] in_proof, uint256[] proof_inputs )
        public view returns (bool)
    {
        Verifier.VerifyingKey memory vk = Verifier.VerifyingKey(
            Pairing.G1Point(in_vk[0], in_vk[1]),
            Pairing.G2Point([in_vk[2], in_vk[3]], [in_vk[4], in_vk[5]]),
            Pairing.G2Point([in_vk[6], in_vk[7]], [in_vk[8], in_vk[9]]),
            Pairing.G2Point([in_vk[10], in_vk[11]], [in_vk[12], in_vk[13]]),
            new Pairing.G1Point[](vk_gammaABC.length / 2)
        );

        for (uint i = 0; i < (vk_gammaABC.length / 2); i++) {
            vk.gammaABC[i] = Pairing.G1Point(vk_gammaABC[(i * 2)], vk_gammaABC[(i * 2) + 1]);
        }

        Verifier.Proof memory proof = Verifier.Proof(
            Pairing.G1Point(in_proof[0], in_proof[1]),
            Pairing.G2Point([in_proof[2], in_proof[3]], [in_proof[4], in_proof[5]]),
            Pairing.G1Point(in_proof[6], in_proof[7])
        );

        return Verifier.Verify( vk, proof, proof_inputs );
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
