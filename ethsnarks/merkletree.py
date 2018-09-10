# Copyright (c) 2018 HarryR
# License: LGPL-3.0+

import hashlib
import math
from collections import defaultdict, namedtuple

from .longsight import LongsightL12p5_MP, curve_order

class MerkleProof(object):
    __slots__ = ('leaf', 'address', 'path', '_hasher')
    def __init__(self, leaf, address, path, hasher):
        self.leaf = leaf
        self.address = address
        self.path = path
        self._hasher = hasher

    def verify(self, root):
        item = self.leaf
        for bit, node in zip(self.address, self.path):
            if bit:
                item = self._hasher.hash_pair(node, item)
            else:
                item = self._hasher.hash_pair(item, node)
        return root == item


class MerkleHasherLongsight(object):
    @classmethod
    def hash_pair(cls, left, right):
        return LongsightL12p5_MP([left, right], 0)

    @classmethod
    def unique(cls, depth, index):
        item = int(depth).to_bytes(2, 'little') + int(index).to_bytes(30, 'little')
        hasher = hashlib.sha256()
        hasher.update(item)
        return int.from_bytes(hasher.digest(), 'big') % curve_order

    @classmethod
    def make_IVs(cls, tree_depth):
        out = []
        hasher = hashlib.sha256()
        for i in range(0, tree_depth):
            item = int(i).to_bytes(2, 'little')
            hasher.update(b'MerkleTree-' + item)
            digest = int.from_bytes(hasher.digest(), 'big') % curve_order
            out.append(digest)
        return out

    @classmethod
    def valid(cls, item):
        return isinstance(item, int) and item > 0 and item < curve_order


class MerkleHasherSHA256(object):
    @classmethod
    def hash_pair(cls, left, right):
        if not cls.valid(left):
            raise ValueError("Left incorrect length!")
        if not cls.valid(right):
            raise ValueError("Right is incorrect length!")
        hasher = hashlib.sha256()
        hasher.update(left)
        hasher.update(right)
        return hasher.digest()

    @classmethod
    def unique(cls, depth, index):
        return int(depth).to_bytes(2, 'little') + int(index).to_bytes(30, 'little')

    @classmethod
    def valid(cls, item):
        return isinstance(item, bytes) and len(item) == 32


class MerkleTree(object):
    def __init__(self, n_items, hasher=None):
        assert n_items > 1
        if hasher is None:
            hasher = MerkleHasherLongsightF
        self._hasher = hasher
        self._n_items = n_items
        self._tree_depth = int(math.log(n_items, 2)) + 1
        self._cur = 0
        self._leaves = [list() for _ in range(0, self._tree_depth + 1)]

    def __len__(self):
        return self._cur

    def append(self, leaf):
        if self._cur >= (self._n_items):
            raise RuntimeError("Tree Full")
        self._leaves[0].append(leaf)
        self._updateTree()
        self._cur += 1
        return self._cur - 1

    def __getitem__(self, key):
        if not isinstance(key, int):
            raise TypeError("Invalid key")
        if key < 0 or key >= self._cur:
            raise KeyError("Out of bounds")
        return self._leaves[0][key]

    def __contains__(self, key):
        return key in self._leaves[0]

    def index(self, leaf):
        return self._leaves[0].index(leaf)

    def proof(self, index):
        leaf = self[index]
        if index >= self._cur:
            raise RuntimeError("Proof for invalid item!")
        address_bits = list()
        merkle_proof = list()
        for i in range(0, self._tree_depth):
            if index % 2 == 0:
                proof_item = self.leaf(i, index + 1)
            else:
                proof_item = self.leaf(i, index - 1)
            address_bits.append( index % 2 )
            merkle_proof.append( proof_item )
            index = index // 2
        return MerkleProof(leaf, address_bits, merkle_proof, self._hasher)

    def _updateTree(self):
        cur_index = self._cur
        for depth in range(0, self._tree_depth):
            next_index = cur_index // 2
            if cur_index % 2 == 0:
                leaf1 = self._leaves[depth][cur_index]
                leaf2 = self.leaf(depth, cur_index + 1)
            else:
                leaf1 = self.leaf(depth, cur_index - 1)
                leaf2 = self._leaves[depth][cur_index]
            node = self._hasher.hash_pair(leaf1, leaf2)
            if len(self._leaves[depth+1]) == next_index:
                self._leaves[depth+1].append(node)
            else:
                self._leaves[depth+1][next_index] = node
            cur_index = next_index

    def leaf(self, depth, offset):
        if offset >= len(self._leaves[depth]):
            leaf = self._hasher.unique(depth, offset)
        else:
            leaf = self._leaves[depth][offset]
        return leaf

    @property
    def root(self):
        if self._cur == 0:
            return None
        return self._leaves[self._tree_depth][0]
