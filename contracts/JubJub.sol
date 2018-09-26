// Copyright (c) 2018 HarryR
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


	/*
	function scalarMult(Point self, uint256 value)
		internal view returns (Point)
	{
		Point memory p = Point(self.x, self.y);
		Point memory a = Point(0, 0);

		while( value != 0 )
		{
			if( (value & 1) != 0 )
			{
				a = pointAdd(a, p);
			}

			p = pointAdd(p, p);

			value = value / 2;
		}

		return a;
	}
	*/


	/*
	function pointDouble(Point self)
		internal view returns (Point)
	{
		return pointAdd(self, self);
	}
	*/


	/**
	* Convert extended affine coordinates to extended twisted edwards coordinates.
	*
	* The axuiliary coordinate is T = XY to represent a point (x,y)
	* on a(x^2) + y^2 = 1 + d(x^2)(y^2) in extended affine coordinates
	* (x,y,t). One can pass the projective representation using the map
	* (x,y,t) -> (x : y : t : ). For all nonzero λ ∈ Q
	*
	*	(X : Y : T : Z) = (λX : λY : λT : λZ)
	*
	* Corresponds to the extended affine point
	*
	*	(X/Z, Y/Z, T/Z)
	*
	* With Z != 0
	*
	* The identity element is represented by (0 : 1 : 0 : 1)
	*
	* The negative of (X : Y : T : Z) is (-X : Y : -T : Z)
	*
	* Given (X : Y : Z) in ε passing to ε^e can be performed by computing:
	*
	*	(XZ, YZ, XY, Z^2)
	*
	* Given (X : Y : T : Z) passing in ε^e to ε is cost-free by simply ignoring T.
	*
	*/


	function jcToEtec( uint256 X, uint256 Y, uint256 Z )
		internal pure returns (uint256, uint256, uint256, uint256)
	{
		uint256 XZ = mulmod(X, Z, Q);
		uint256 YZ = mulmod(Y, Z, Q);
		uint256 XY = mulmod(X, Y, Q);
		uint256 Z2 = mulmod(Z, Z, Q);

		return (XZ, YZ, XY, Z2);
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


	function eacToPoint( uint256 X, uint256 Y, uint256 T )
		internal pure returns (uint256, uint256)
	{
		return (X, Y);
	}


	// section 3.1 - Unified addition
	function etecDouble( uint256 X, uint256 Y, uint256 T, uint256 Z )
		internal pure returns (uint256, uint256, uint256, uint256)
	{
		uint256 A = mulmod(X, X, Q);

		uint256 B = mulmod(Y, Y, Q);

		uint256 C = mulmod(mulmod(JUBJUB_D, T, Q), T, Q);

		uint256 D = mulmod(Z, Z, Q);

		uint256 E = addmod(X,Y,Q);
		E = mulmod(E, E, Q);
		E = submod(E, A, Q);
		E = submod(E, B, Q);

		uint256 F = submod(D, C, Q);

		uint256 G = addmod(D, C, Q);

		uint256 H = submod(B, mulmod(JUBJUB_A, A, Q), Q);

		uint256 X3 = mulmod(E, F, Q);

		uint256 Y3 = mulmod(G, H, Q);

		uint256 T3 = mulmod(E, H, Q);

		uint256 Z3 = mulmod(F, G, Q);

		return (X3, Y3, T3, Z3);
	}


	/*
	* Taken from https://cr.yp.to/newelliptic/newelliptic-20070906.pdf
	* - section 4 page 10, "Doubling"
	*/
	function jcDouble(uint256 X, uint256 Y, uint256 Z)
		internal view returns (uint256 X3, uint256 Y3, uint256 Z3)
	{
		uint256 c = 1;
		uint256 B = addmod(X, Y, Q);
		B = mulmod(B, B, Q);				// B = (X+Y)^2

		uint256 C = mulmod(X, X, Q);		// C = X^2

		uint256 D = mulmod(Y, Y, Q);		// D = Y^2

		uint256 E = addmod(C, D, Q);		// E = C+D

		uint256 H = mulmod(c, Z, Q);		//      c+Z
		H = mulmod(H, H, Q);				// H = (c+Z)^2

		uint256 J = addmod(H, H, Q);		//         2H
		J = submod(E, J, Q);				// J = E - 2H

		X3 = submod(B, E, Q);				//         B-E
		X3 = mulmod(c, X3, Q);				//      c*(B-E)
		X3 = mulmod(X3, J, Q);				// X3 = c*(B-E)*J

		Y3 = submod(C, D, Q);				//           C-D
		Y3 = mulmod(E, Y3, Q);				//        E*(C-D)
		Y3 = mulmod(c, Y3, Q);				// Y3 = c*E*(C-D)

		Z3 = mulmod(E, J, Q);				// Z3 = E*J
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
