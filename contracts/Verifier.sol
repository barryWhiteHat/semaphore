// this code is taken from https://github.com/JacobEberhardt/ZoKrates 

pragma solidity 0.4.24;

import "./Pairing.sol";

library Verifier
{
    using Pairing for Pairing.G1Point;
    using Pairing for Pairing.G2Point;

    function ScalarField ()
        public pure returns (uint256)
    {
        return 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    }

    struct VerifyingKey
    {
        Pairing.G1Point alpha;
        Pairing.G2Point beta;
        Pairing.G2Point gamma;
        Pairing.G2Point delta;
        Pairing.G1Point[] gammaABC;
    }

    struct Proof
    {
        Pairing.G1Point A;
        Pairing.G2Point B;
        Pairing.G1Point C;
    }

    struct ProofWithInput
    {
        Proof proof;
        uint256[] input;
    }

    function Verify (VerifyingKey memory vk, ProofWithInput memory pwi)
        internal returns (bool)
    {
        return Verify(vk, pwi.proof, pwi.input);
    }

    function Verify (VerifyingKey memory vk, Proof memory proof, uint256[] memory input)
        internal returns (bool)
    {
        require(input.length + 1 == vk.gammaABC.length);

        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = vk.gammaABC[0];
        for (uint i = 0; i < input.length; i++)
            vk_x = Pairing.pointAdd(vk_x, Pairing.pointMul(vk.gammaABC[i + 1], input[i]));

        // Verify proof
        return Pairing.pairingProd4(
            proof.A, proof.B,
            vk_x.negate(), vk.gamma,
            proof.C.negate(), vk.delta,
            vk.alpha.negate(), vk.beta);
    }
}
