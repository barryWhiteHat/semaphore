// this code is taken from https://github.com/JacobEberhardt/ZoKrates 

pragma solidity ^0.4.24;

import "./Pairing.sol";

library Verifier
{
    using Pairing for Pairing.G1Point;
    using Pairing for Pairing.G2Point;

    struct VerifyingKey
    {
        Pairing.G2Point A;
        Pairing.G1Point B;
        Pairing.G2Point C;
        Pairing.G2Point gamma;
        Pairing.G1Point gammaBeta1;
        Pairing.G2Point gammaBeta2;
        Pairing.G2Point Z;
        Pairing.G1Point[] IC;
    }

    struct Proof
    {
        Pairing.G1Point A;
        Pairing.G1Point A_p;
        Pairing.G2Point B;
        Pairing.G1Point B_p;
        Pairing.G1Point C;
        Pairing.G1Point C_p;
        Pairing.G1Point K;
        Pairing.G1Point H;
        uint256[] input;
    }

    function Verify (VerifyingKey memory vk, Proof memory proof)
        internal returns (uint)
    {
        require(proof.input.length + 1 == vk.IC.length);

        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = vk.IC[0];

        for (uint i = 0; i < proof.input.length; i++)
            vk_x = Pairing.pointAdd(vk_x, Pairing.pointMul(vk.IC[i + 1], proof.input[i]));

        if (!Pairing.pairingProd2(proof.A, vk.A, Pairing.negate(proof.A_p), Pairing.P2()))
            return 1;

        if (!Pairing.pairingProd2(vk.B, proof.B, Pairing.negate(proof.B_p), Pairing.P2()))
            return 2;

        if (!Pairing.pairingProd2(proof.C, vk.C, Pairing.negate(proof.C_p), Pairing.P2()))
            return 3;

        if (!Pairing.pairingProd3(
            proof.K, vk.gamma,
            Pairing.negate(Pairing.pointAdd(vk_x, Pairing.pointAdd(proof.A, proof.C))), vk.gammaBeta2,
            Pairing.negate(vk.gammaBeta1), proof.B
        )) return 4;

        if (!Pairing.pairingProd3(
                Pairing.pointAdd(vk_x, proof.A), proof.B,
                Pairing.negate(proof.H), vk.Z,
                Pairing.negate(proof.C), Pairing.P2()
        )) return 5;

        return 0;
    }

    function InitProofFromArgs(
            Proof memory proof,
            uint[2] a,
            uint[2] a_p,
            uint[2][2] b,
            uint[2] b_p,
            uint[2] c,
            uint[2] c_p,
            uint[2] h,
            uint[2] k,
            uint[] input
        )
        internal pure
    {
        proof.A = Pairing.G1Point(a[0], a[1]);
        proof.A_p = Pairing.G1Point(a_p[0], a_p[1]);
        proof.B = Pairing.G2Point([b[0][0], b[0][1]], [b[1][0], b[1][1]]);
        proof.B_p = Pairing.G1Point(b_p[0], b_p[1]);
        proof.C = Pairing.G1Point(c[0], c[1]);
        proof.C_p = Pairing.G1Point(c_p[0], c_p[1]);
        proof.H = Pairing.G1Point(h[0], h[1]);
        proof.K = Pairing.G1Point(k[0], k[1]);

        proof.input = new uint256[](input.length);
        for( uint i = 0; i < input.length; i++ ) {
            proof.input[i] = input[i];
        }
    } 
}
