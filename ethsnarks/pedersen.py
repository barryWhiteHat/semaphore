"""
This module implements a Pedersen hash function.
It can hash points, scalar values or blocks of message data.

It is possible to create two variants, however only the
non-homomorphic variant has been implemented.

The homomorphic variant users the same base point for every
input, whereas the non-homomorphic version uses a different
base point for every input.

For example to non-homomorphically hash the two points P1 and P2

	Four base points are chosen (consistently)

		B0, B1, B2, B3

	The result of the hash is the point:

		B0*P1.x + B1*P1.y + B2*P2.x + B3*P2.y

To homomorphically hash the two points:

	Two base points are chosen

		BX, BY

	The result of the hash is the point:

		BX*P1.x + BY.P1.y + BX.P2.x + BY.P2.y

	The hash will be the same if either point is swapped
	with the other, e.g. H(P1,P2) is the same as H(P2,P1).
"""

import math
from struct import pack

from .jubjub import Point, JUBJUB_L


MAX_SEGMENT_BITS = math.floor(math.log2(JUBJUB_L))
MAX_SEGMENT_BYTES = MAX_SEGMENT_BITS // 8


def pedersen_hash_basepoint(name, i):
	"""
	Create a base point for use with the windowed pedersen
	hash function.
	The name and sequence numbers are used a unique identifier.
	Then HashToPoint is run on the name+seq to get the base point

	XXX: Ethereum compatible
	"""
	seq = pack('>L', i)
	max_name_len = MAX_SEGMENT_BYTES - len(seq)
	if not isinstance(name, bytes):
		raise TypeError("Name not bytes")
	if len(name) > max_name_len:
		raise ValueError("Name too long")
	padding_needed = (max_name_len - len(name)) % max_name_len
	data = bytes(padding_needed) + seq
	return Point.from_hash(data)


def pedersen_hash_points(name, *points):
	# XXX: should the coordinate be truncated?
	result = Point.infinity()
	for i, p in enumerate(points):
		p = p.as_point()
		for j, c in enumerate([p.x, p.y]):
			base = pedersen_hash_basepoint(name, i*2 + j)
			result += base * c
	return result


def pedersen_hash_scalars(name, *scalars):
	result = Point.infinity()
	for i, s in enumerate(scalars):
		if s >= JUBJUB_L:
			raise ValueError("Scalar must be below L")
		if s <= 0:
			raise ValueError("Scalar must be above zero")
		base = pedersen_hash_basepoint(name, i)
		result += base * s
	return result


def pedersen_hash_bytes(name, *args):
	"""
	Split the message data into segments, then hash each segment

	Data is split into bytes for convenience, rather
	than bits. e.g. if snark scalar field is 253 bits
	then only 248 will be used (31 bytes), the reason is:

		1) Conversion is easier
		2) All values are below L (location of the curve twist)
	"""
	data = b''.join(args)
	segments_list = [data[i:i+MAX_SEGMENT_BYTES]
					 for i in range(0, len(data), MAX_SEGMENT_BYTES)]
	result = Point.infinity()
	for i, segment in enumerate(segments_list):
		base = pedersen_hash_basepoint(name, i)
		scalar = int.from_bytes(segment, 'big')
		result += base * scalar
	return result
