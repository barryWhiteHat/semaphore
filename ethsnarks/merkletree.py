import hashlib
import math
from collections import defaultdict, namedtuple


class MerkleProof(object):
    __slots__ = ('leaf', 'address', 'path', 'hashfn')
    def __init__(self, leaf, address, path, hashfn):
        self.leaf = leaf
        self.address = address
        self.path = path
        self.hashfn = hashfn

    def verify(self, root):
        item = self.leaf
        for bit, node in zip(self.address, self.path):
            if bit:
                item = self.hashfn(node, item)
            else:
                item = self.hashfn(item, node)
        return root == item


def _hash_pair_sha256(left, right):
    if len(left) != 32:
        raise ValueError("Left incorrect length!")
    if len(right) != 32:
        raise ValueError("Right is incorrect length!")
    hasher = hashlib.sha256()
    hasher.update(left)
    hasher.update(right)
    return hasher.digest()


class MerkleTree(object):
    def __init__(self, n_items, hashfn=None, null_leaf=None):
        if hashfn is None:
            hashfn = _hash_pair_sha256
            null_leaf = b'\0' * 32
        self._null_leaf = null_leaf
        self._hashfn = hashfn
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

    def __getitem__(self, key):
        if not isinstance(key, int):
            raise TypeError("Invalid key")
        if key < 0 or key >= self._cur:
            raise KeyError("Out of bounds")
        return self._leaves[0][key]

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
                proof_item = self._getUniqueLeaf(i, index + 1)
            else:
                proof_item = self._getUniqueLeaf(i, index - 1)
            address_bits.append( index % 2 )
            merkle_proof.append( proof_item )
            index = index // 2
        return MerkleProof(leaf, address_bits, merkle_proof, self._hashfn)

    def _updateTree(self):
        cur_index = self._cur
        for depth in range(0, self._tree_depth):
            next_index = cur_index // 2
            if cur_index % 2 == 0:
                leaf1 = self._leaves[depth][cur_index]
                leaf2 = self._getUniqueLeaf(depth, cur_index + 1)
            else:
                leaf1 = self._getUniqueLeaf(depth, cur_index - 1)
                leaf2 = self._leaves[depth][cur_index]
            node = self._hashfn(leaf1, leaf2)
            if len(self._leaves[depth+1]) == next_index:
                self._leaves[depth+1].append(node)
            else:
                self._leaves[depth+1][next_index] = node
            cur_index = next_index

    def _getUniqueLeaf(self, depth, offset):
        if offset >= len(self._leaves[depth]):
            leaf = int(depth).to_bytes(2, 'little') + int(offset).to_bytes(30, 'little')
        else:
            leaf = self._leaves[depth][offset]
        return leaf

    def getLeaf(self, depth, offset):
        return self._leaves[depth][offset]

    @property
    def root(self):
        if self._cur == 0:
            return None
        return self._leaves[self._tree_depth][0]
