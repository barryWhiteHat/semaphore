// Copyright (c) 2018 HarryR
// License: LGPL-3.0+

pragma solidity ^0.4.19;

library JubJub
{
	uint256 constant JUBJUB_A = 168700;
	uint256 constant JUBJUB_D = 168696;
	uint256 constant COFACTOR = 8;

	uint256 constant Q = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
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
