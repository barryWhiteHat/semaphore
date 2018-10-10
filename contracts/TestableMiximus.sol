pragma solidity 0.4.24;
pragma experimental ABIEncoderV2;


import "./Miximus.sol";
import "./Verifier.sol";


// Please note, it saves a lot of gas to use the `vk2sol`
// utility to generate Solidity code, hard-coding the
// verifying key avoids the cost of loading from storage.

contract TestableMiximus is Miximus
{
    Verifier.VerifyingKey m_vk;

    constructor( uint256[2] alpha, uint256[2][2] beta, uint256[2][2] gamma, uint256[2][2] delta, uint256[] gammaABC )
        public
    {
        m_vk.alpha = Pairing.G1Point(alpha[0], alpha[1]);
        m_vk.beta = Pairing.G2Point(beta[0], beta[1]);
        m_vk.gamma = Pairing.G2Point(gamma[0], beta[1]);
        m_vk.delta = Pairing.G2Point(delta[0], delta[1]);

        uint n_abc = gammaABC.length / 2;
        for( uint i = 0; i < n_abc; i += 2 )
        {
            m_vk.gammaABC.push( Pairing.G1Point(gammaABC[i], gammaABC[i+1]) );
        }
    }

    function GetVerifyingKey (Verifier.VerifyingKey memory out_vk)
        internal view
    {
        out_vk = m_vk;
    }
}
