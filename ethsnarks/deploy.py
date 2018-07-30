
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

import pdb
import json
import random 

from ctypes import cdll
import ctypes as c

from solc import compile_source, compile_files, link_code
from bitstring import BitArray

from .utils import genMerkelTree, getMerkelProof, hashPadded


tree_depth = 2
_lib_miximus = cdll.LoadLibrary('build/src/libmiximus.so')


prove = _lib_miximus.prove
prove.argtypes = [((c.c_bool*256)*(tree_depth + 3)), (c.c_bool*256), (c.c_bool*256) , (c.c_bool*256), c.c_int, ((c.c_bool*tree_depth)), c.c_int, c.c_int, c.c_char_p] 
prove.restype = c.c_char_p

genKeys = _lib_miximus.genKeys
genKeys.argtypes = [c.c_int, c.c_char_p, c.c_char_p]

_lib_miximus_verify = _lib_miximus.verify
_lib_miximus_verify.argtypes = [c.c_char_p, c.c_char_p]
_lib_miximus_verify.restype = c.c_bool


def binary2ctypes(out):
    return((c.c_bool*256)(*out))


def hexToBinary(hexString):
    out = [ int(x) for x in bin(int(hexString, 16))[2:].zfill(256)]
    return(binary2ctypes(out))


def native_verify(vk, proof):
    vk_cstr = c.c_char_p(vk.encode('ascii'))
    proof_cstr = c.c_char_p(proof.encode('ascii'))
    return _lib_miximus_verify(vk_cstr, proof_cstr)


def checkProof(vk, proof):
    return native_verify(json.dumps(vk), json.dumps(proof))


def genWitness(leaves, nullifier, sk, signal, signal_variables, external_nullifier, address, tree_depth, fee, pk_dir):

    path = []
    address_bits = []

    root , merkle_tree = genMerkelTree(tree_depth, leaves)
    path1 , address_bits1 = getMerkelProof(leaves, address, tree_depth)

    path = [hexToBinary(x) for x in path1]

    address_bits = address_bits1[::-1]
    print(path1, address_bits, address_bits, root, leaves, sk, nullifier)

    path = path[::-1]

    path.append(hexToBinary(nullifier))
    path.append(hexToBinary(sk))
    path.append(hexToBinary(root))

    print ("address bits ",  address_bits)

    path  = ((c.c_bool*256)*(tree_depth + 3))(*path)
    address = int("".join([str(int(x)) for x in address_bits]),2)

    address_bits = (c.c_bool*tree_depth)(*address_bits)

    signal = (c.c_bool*256) (*hexToBinary(signal))
    signal_variables = (c.c_bool*256) (*hexToBinary(signal_variables))
    external_nullifier = (c.c_bool*256) (*hexToBinary(external_nullifier))
    fee =  c.c_int(fee)
    proof = prove(path, signal, signal_variables, external_nullifier, address, address_bits, tree_depth, fee,  c.c_char_p(pk_dir.encode()))
    proof = json.loads(proof.decode("utf-8"))

    return(proof, root)

def genSalt(i):
    salt = [random.choice("0123456789abcdef") for x in range(0,i)]
    out = "".join(salt)
    return(out)
