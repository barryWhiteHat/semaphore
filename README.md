# EthSnarks

## Building

Type `make` - the first time you run it will retrieve submodules, setup cmake and build everything.

The following dependencies (for Linux) are needed:

 * GNU make
 * cmake
 * g++ or clang++
 * gmp
 * boost

# Components

## Unique Merkle Proof

This circuit implements a generic mechanism of proving ownership of an unobservable item within a merkle tree while ensuring that any proof made twice can be identified.

Every leaf of the merkle tree consists of two components:

 * a - public
 * b - secret

The leaf is `HASH(a, HASH(b))`, this commitment scheme is flexible, two parties can agree on the value of a leaf in private without revealing enough information for one side to create a proof. e.g. Alice creates a random salt for `a`, Bob provides the hash of `b`, Alice shows that `leaf = HASH(a, HASH(b))` but she can't create a proof without knowing `b` which only Bob does.

Because `a` is public at the time of verification the observer can prevent the proof from being accepted twice, however it remains impossible to link that proof back to any leaf in the tree without also knowing the preimage `b`.

### Merkle Proof circuit pseudo-code

```python
def circuit(public_root, private_path, public_a, secret_b, public_args_hashed):
	leaf = HASH(public_a, HASH(secret_b))
	return public_root == merkle_prove(leaf, private_path)
```

## Linkable Merkle Proof

This circuit allows for the same leaf in the merkle tree to be proven multiple times without revealing it, however any two proofs with the same `public_args_hashed` will be observable as being the same.

```python
def circuit(public_root, private_path, public_tag, public_unique_args, secret_b, public_args):
	leaf = HASH(secret_b)
	path_ok = public_root == merkle_prove(leaf, private_path)
	tag_ok = public_tag == HASH(secret_b, public_unique_args)
	return path_ok and tag_ok
```