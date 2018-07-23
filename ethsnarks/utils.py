'''
    copyright 2018 to the Semaphore Authors

    This file is part of Semaphore.

    Semaphore is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Semaphore is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Semaphore.  If not, see <https://www.gnu.org/licenses/>.
'''


import hashlib
import random
from binascii import hexlify


def libsnark2python (inputs):   
    #flip the inputs

    bin_inputs = []
    for x in inputs:
        binary = bin(x)[2:][::-1]
        if len(binary) > 100:
            binary = binary.ljust(253, "0")          
        bin_inputs.append(binary)
    raw = "".join(bin_inputs)

    raw += "0" * (256 * 5 - len(raw)) 

    output = []
    i = 0
    while i < len(raw):
        hexnum = hex(int(raw[i:i+256], 2))
        #pad leading zeros
        padding = 66 - len(hexnum)
        hexnum = hexnum[:2] + "0"*padding + hexnum[2:]

        output.append(hexnum)
        i += 256
    return(output)


def hashPadded(left, right):
    x1 = int(left , 16).to_bytes(32, "big")
    x2 = int(right , 16).to_bytes(32, "big")    
    data = x1 + x2
    answer = hashlib.sha256(data).hexdigest()
    return("0x" + answer)


def sha256(data):
    data = str(data).encode()
    return("0x" + hashlib.sha256(data).hexdigest())


def getUniqueLeaf(depth):
    inputHash = "0x0000000000000000000000000000000000000000000000000000000000000000"
    for i in range(0, depth):
        inputHash = hashPadded(inputHash, inputHash)
    return(inputHash)


def genMerkelTree(tree_depth, leaves):
    tree_layers = [leaves ,[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[]] 
    for i in range(0, tree_depth):
        if len(tree_layers[i]) % 2 != 0:
            tree_layers[i].append(getUniqueLeaf(i))
        for j in range(0, len(tree_layers[i]), 2):
            tree_layers[i+1].append(hashPadded(tree_layers[i][j], tree_layers[i][j+1]))

    return(tree_layers[tree_depth][0], tree_layers)


def getMerkelProof(leaves, index, tree_depth):
    address_bits = []
    merkelProof = []
    mr , tree = genMerkelTree(tree_depth, leaves)
    for i in range(0 , tree_depth):
        address_bits.append(index%2)
        if (index%2 == 0): 
            merkelProof.append(tree[i][index + 1])
        else:
            merkelProof.append(tree[i][index - 1])
        index = int(index/2);
    return(merkelProof, address_bits); 


def genSalt(n):
    chars = [_ for _ in 'abcdef0123456789']
    return ''.join([random.choice(chars) for _ in range(0, n)])


def initMerkleTree(i):
    nullifiers = []
    sks = []
    leaves = []
    for j in range (0, i):
        nullifiers.append("0x" + genSalt(64))
        sks.append("0x" + genSalt(64))
        leaves.append(hashPadded(nullifiers[j], sks[j]))
    return(leaves, nullifiers, sks)
