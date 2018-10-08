import math
from hashlib import sha256
from .field import FQ
from .jubjub import Point, JUBJUB_L, JUBJUB_Q, JUBJUB_ORDER

"""
Implements EdDSA

The signer has two secret values:

	* k = Secret key
	* r = Per-(message,key) nonce

The signer provides a signature consiting of two pars:

	* R = Point, image of `r*B`
	* s = Image of `r + (k*t)`

The signer provides the verifier with their public key:

	* A = k*R

Both the verifier and the signer calculate the common reference string:

	* t = H(R, A, m)

The nonce `r` is secret, and protects the value `s` from revealing the
signers secret key.
"""


def encodeint(y):
	b = 253
	bits = [(y >> i) & 1 for i in range(b)]
	data = [bytes([sum([bits[i * 8 + j] << j for j in range(8)])]) for i in range(b//8)]
	return b''.join(data)


def make_bytes(arg):
	if isinstance(arg, bytes):
		return arg
	elif isinstance(arg, FQ):
		return encodeint(arg.n)
	elif isinstance(arg, Point):
		return make_bytes(arg.x) + make_bytes(arg.y)
	raise TypeError("Cannot convert unknown type to bytes: " + str(type(arg)))


def HashToBytes(*args):
	return sha256(b''.join([make_bytes(_) for _ in args])).digest()


def HashToInt(*args):
	"""
	Hashes arguments, returns first 250 least significant bits
	"""
	# Verify that any 250 bits will be less than `L`
	assert math.ceil(math.log2(JUBJUB_L)) > 250
	data = HashToBytes(*args)
	value = int.from_bytes(data, 'big')
	mask = (2<<249) - 1
	return value & mask


def eddsa_verify(A, R, s, m, B):
	"""
	@param A public key
	@param R Signature point
	@param s Signature scalar
	@param m Message being signed
	@param B base point
	"""
	assert isinstance(R, Point)
	#assert isinstance(s, FQ)
	A = A.as_point()

	assert s < JUBJUB_Q

	mhash = HashToBytes(m)
	t = HashToInt(R, A, mhash)
	lhs = B * s
	rhs = R + (A * t)
	return lhs == rhs


def eddsa_sign(m, k, B, A=None):
	"""
	@param m Message being signed
	@param k secret key
	@param B base point
	"""	
	assert isinstance(k, FQ)
	assert k.n < JUBJUB_L
	assert k.n > 0

	if A is None:
		A = k * B

	mhash = HashToBytes(m)
	khash = HashToBytes(k)
	r = HashToInt(khash, mhash)
	R = B * r
	t = HashToInt(R, A, mhash)
	s = ((k.n*t) + r) % JUBJUB_ORDER
	return [R, s]
