// Copyright (c) 2018 @HarryR
// Copyright (c) 2018 @yondonfu
// License: LGPL-3.0+

pragma solidity ^0.4.19;

library JubJub
{
	// A should be a square in Q
	uint256 constant JUBJUB_A = 168700;

	// D should not be a square in Q
	uint256 constant JUBJUB_D = 168696;

	uint256 constant COFACTOR = 8;

	// XXX: is Q square?
	uint256 constant Q = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

	// XXX: is R square?
	uint256 constant R = 2736030358979909402780800718157159386076813972158567259200215660948447373041;

	struct Point {
		uint x;
		uint y;
	}


	function submod(uint256 a, uint256 b, uint256 modulus)
		internal pure returns (uint256)
	{
		uint256 n = a;

		if( a <= b )
			n += modulus;

		return (n - b) % modulus;
	}


	function modexp(uint256 base, uint256 exponent, uint256 modulus)
		internal view returns (uint256)
	{
		uint256[1] memory output;
		uint256[6] memory input;
		input[0] = 0x20;
		input[1] = 0x20;
		input[2] = 0x20;
		input[3] = base;
		input[4] = exponent;
		input[5] = modulus;

		bool success;
		assembly {
			success := staticcall(sub(gas, 2000), 5, input, 0xc0, output, 0x20)			
		}
		require(success);
		return output[0];
	}


	function inv(uint256 value, uint256 field_modulus)
		internal view returns (uint256)
	{
		return modexp(value, field_modulus - 2, field_modulus);
	}


	function scalarMult(uint256 x, uint256 y, uint256 value)
		internal view returns (uint256, uint256)
	{
		uint256 px;
		uint256 py;
		uint256 pt;
		uint256 pz = 1;
		(px, py, pt) = pointToEac(x, y);

		uint256[4] memory a = [uint256(0), uint256(0), uint256(0), uint256(1)];

		while( value != 0 )
		{
			if( (value & 1) != 0 )
			{
				a = etecAdd(a, [px, py, pt, pz]);
			}

			(px, py, pt, pz) = etecDouble(px, py, pt, pz);

			value = value / 2;
		}

		return etecToPoint(px, py, pt, pz);
	}


	/**
	* Project X,Y point to extended affine coordinates
	*/
	function pointToEac( uint256 X, uint256 Y )
		internal pure returns (uint256, uint256, uint256)
	{
		return (X, Y, mulmod(X, Y, Q));
	}


	/**
	* Extended twisted edwards coordinates to extended affine coordinates
	*/
	function etecToEac( uint256 X, uint256 Y, uint256 T, uint256 Z )
		internal view returns (uint256, uint256, uint256)
	{
		Z = inv(Z, Q);
		return (mulmod(X, Z, Q), mulmod(Y, Z, Q), mulmod(T, Z, Q));
	}


	/**
	* Extended twisted edwards coordinates to extended affine coordinates
	*/
	function etecToPoint( uint256 X, uint256 Y, uint256 T, uint256 Z )
		internal view returns (uint256, uint256)
	{
		Z = inv(Z, Q);
		return (mulmod(X, Z, Q), mulmod(Y, Z, Q));
	}


	function eacToPoint( uint256 X, uint256 Y, uint256 T )
		internal pure returns (uint256, uint256)
	{
		return (X, Y);
	}


    /**
     * @dev Add 2 etec points on baby jubjub curve
     * x3 = (x1y2 + y1x2) * (z1z2 - dt1t2)
     * y3 = (y1y2 - ax1x2) * (z1z2 + dt1t2)
     * t3 = (y1y2 - ax1x2) * (x1y2 + y1x2)
     * z3 = (z1z2 - dt1t2) * (z1z2 + dt1t2)
     */
    function etecAdd(uint256[4] _p1, uint256[4] _p2)
    	internal pure returns (uint256[4] p3)
    {
        if (_p1[0] == 0 && _p1[1] == 0 && _p1[2] == 0 && _p1[3] == 0) {
            return _p2;
        }

        if (_p2[0] == 0 && _p2[1] == 0 && _p2[2] == 0 && _p2[3] == 0) {
            return _p1;
        }

        uint256[2] memory intermediates;
        // A <- x1 * x2
        intermediates[0] = mulmod(_p1[0], _p2[0], Q);

        // B <- y1 * y2
        intermediates[1] = mulmod(_p1[1], _p2[1], Q);

        // C <- d * t1 * t2
        uint256 C = mulmod(mulmod(JUBJUB_D, _p1[2], Q), _p2[2], Q);

        // D <- z1 * x2
        uint256 D = mulmod(_p1[3], _p2[3], Q);

        // E <- (x1 + y1) * (x2 + y2) - A - B
        uint256 E = submod(submod(mulmod(addmod(_p1[0], _p1[1], Q), addmod(_p2[0], _p2[1], Q), Q), intermediates[0], Q), intermediates[1], Q);

        // F <- D - C
        //uint256 F = submod(D, C, Q);
        uint256 F = D;
        if( F <= C )
        	F += Q;
        F = (F - C) % Q;

        // G <- D + C
        uint256 G = addmod(D, C, Q);

        // H <- B - a * A
        uint256 H = submod(intermediates[1], mulmod(JUBJUB_A, intermediates[0], Q), Q);

        // x3
        p3[0] = mulmod(E, F, Q);
        // y3
        p3[1] = mulmod(G, H, Q);
        // t3
        p3[2] = mulmod(E, H, Q);
        // z3
        p3[3] = mulmod(F, G, Q);
    }


    /**
     * @dev Double a etec point using dedicated double algorithm
     */
    function pointDoubleDedicatedASM(
        uint256 _x, 
        uint256 _y,
        uint256 _t,
        uint256 _z
    ) 
        internal 
        pure
        returns (uint256 x, uint256 y, uint256 t, uint256 z)
    {
        assembly {
            let localQ := 0x30644E72E131A029B85045B68181585D2833E84879B9709143E1F593F0000001 
            let localA := 0x292FC

            // A <- x1 * x1
            let a := mulmod(_x, _x, localQ)
            // B <- y1 * y1
            let b := mulmod(_y, _y, localQ)
            // C <- 2 * z1 * z1
            let c := mulmod(mulmod(2, _z, localQ), _z, localQ)
            // D <- a * A
            let d := mulmod(localA, a, localQ)
            // E <- (x1 + y1)^2 - A - B
            let e := addmod(_x, _y, localQ)
            e := mulmod(e, e, localQ)
            if lt(e, add(a, 1)) {
                e := add(e, localQ)
            }
            e := mod(sub(e, a), localQ)
            if lt(e, add(b, 1)) {
                e := add(e, localQ)
            }
            e := mod(sub(e, b), localQ)
            // G <- D + B
            let g := addmod(d, b, localQ)
            // F <- G - C
            let f := g
            if lt(f, add(c, 1)) {
                f := add(f, localQ)
            }
            f := mod(sub(f, c), localQ)
            // H <- D - B
            let h := d
            if lt(h, add(b, 1)) {
                h := add(h, localQ)
            }
            h := mod(sub(h, b), localQ)

            // x3 <- E * F
            x := mulmod(e, f, localQ)
            // y3 <- G * H
            y := mulmod(g, h, localQ)
            // t3 <- E * H
            t := mulmod(e, h, localQ)
            // z3 <- F * G
            z := mulmod(f, g, localQ)
        }
    }


	function etecDoubleIntermediate( uint256 X, uint256 Y, uint256 T, uint256 Z )
		internal pure returns (uint256 E, uint256 F, uint256 G, uint256 H)
	{
		G = mulmod(X, X, Q);
		F = mulmod(Y, Y, Q);
		E = addmod(X, Y, Q);

		//E = submod(mulmod(E, E, Q), G, Q);
		E = mulmod(E, E, Q);
		if( E <= G )
			E += Q;
		E = (E - G) % Q;

		//E = submod(E, F, Q);
		if( E <= F )
			E += Q;
		E = (E - F) % Q;

		H = submod(F, mulmod(JUBJUB_A, G, Q), Q);

		Z = mulmod(Z, Z, Q);
		G = mulmod(mulmod(JUBJUB_D, T, Q), T, Q);

		//F = submod(Z, G, Q);
		F = Z;
		if( F <= G )
			F += Q;
		F = (F - G) % Q;

		G = addmod(Z, G, Q);
	}


	// section 3.1 - Unified addition
	function etecDouble( uint256 X, uint256 Y, uint256 T, uint256 Z )
		internal pure returns (uint256, uint256, uint256, uint256)
	{
		(X, Y, T, Z) = etecDoubleIntermediate(X, Y, T, Z);
		return (mulmod(X, Y, Q), mulmod(T, Z, Q), mulmod(X, Z, Q), mulmod(Y, T, Q));
	}


	function pointAdd(uint256[2] self, uint256[2] other)
		internal view returns (uint256[2])
	{
		if( self[0] == 0 && self[1] == 0 ) {
			return other;
		}
		else if( other[0] == 0 && other[1] == 0 ) {
			return self;
		}

		uint256 x1x2 = mulmod(self[0], other[0], Q);
		uint256 y1y2 = mulmod(self[1], other[1], Q);

		// ----------------		

		// 		    (x1*y2 + y1*x2)
		uint256 x3_lhs = addmod(mulmod(self[0], other[1], Q), mulmod(self[1], other[0], Q), Q);

		// 									  JUBJUB_D*x1*x2*y1*y2
		uint256 dx1x2y1y2 = mulmod(mulmod(JUBJUB_D, x1x2, Q), y1y2, Q);

		// 						    (Fq.ONE + JUBJUB_D*u1*u2*v1*v2)
		uint256 x3_rhs = addmod(1, dx1x2y1y2, Q);

		//						    (Fq.ONE - JUBJUB_D*u1*u2*v1*v2)
		uint256 y3_rhs = submod(1, dx1x2y1y2, Q);


		// 			(y1*y2 - A*x1*x2)
		uint256 y3_lhs = submod(y1y2, mulmod(JUBJUB_A, x1x2, Q), Q);

		// ----------------

		// lhs / rhs
		return [
			// x3 = (x1*y2 + y1*x2)   / (Fq.ONE + D*x1*x2*y1*y2)
			mulmod(x3_lhs, inv(x3_rhs, Q), Q),

			// y3 = (y1*y2 - A*x1*x2) / (Fq.ONE - D*x1*x2*y1*y2)
			mulmod(y3_lhs, inv(y3_rhs, Q), Q)
		];
	}
}
