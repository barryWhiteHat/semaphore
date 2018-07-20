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
import time
import random

from .deploy import *
from .utils import genMerkelTree, sha256
from .contract_deploy import *  

if __name__ == "__main__":

    pk_output = "../zksnark_element/pk.raw"
    vk_output = "../zksnark_element/vk.json"

    # perform the trusted setup making hte proving key ,  verification key
    genKeys(c.c_int(tree_depth), c.c_char_p(pk_output.encode()) , c.c_char_p(vk_output.encode()))


    #part 1 merkel tree setup which act as the census of the vote
    #make merkel Tree with 10 members
    #This is a trusted part but it can be varified by the users before teh 
    
    leaves, nullifiers, sks = initMerkleTree(1) 
    root, layers = genMerkelTree(29, leaves) 

    #part 2 definition of the vote properties.
    # You "sign" signal 1 to vote for canditate 1
    signal1 = sha256({"NomimatedSpokesPersonFor":root , "candidate": "Candidate1" })
    # You "sign" signal 2 to vote for candidate 2
    signal2 = sha256({"NomimatedSpokesPersonFor":root , "candidate": "Candidate2" })
    # You use external_nullifier to enforce one person (merkle tree memeber) one signal
    external_nullifier = sha256("nomimatedSpokesPerson"+root+str(time.time()))
    # We use signal_variables as a nonce so that you can update your vote.
    # But we do not implment this logic when counting votes as it makes to flow a little complicated
    signal_variables = sha256(str(1))
    # now we deploy the verification contract
    contract  = contract_deploy(29, "../zksnark_element/vk.json", root)

    # Here we do the actual voteing 
    proofs = []
    for address, (nullifier , sk) in enumerate(zip(nullifiers, sks)):
        rand = int(random.uniform(1, 3)) 
        if rand == rand:
            signal = signal1
        else:
            signal = signal2
        proof, root = genWitness(leaves, nullifier, sk, signal , signal_variables, external_nullifier, address, tree_depth, 0, "../zksnark_element/pk.raw", False)
        proofs.append(proof)

    for proof in proofs:
        proof["a"] = hex2int(proof["a"])
        proof["a_p"] = hex2int(proof["a_p"])
        proof["b"] = [hex2int(proof["b"][0]), hex2int(proof["b"][1])]
        proof["b_p"] = hex2int(proof["b_p"])
        proof["c"] = hex2int(proof["c"])
        proof["c_p"] = hex2int(proof["c_p"])
        proof["h"] = hex2int(proof["h"])
        proof["k"] = hex2int(proof["k"])
        proof["input"] = hex2int(proof["input"])   

        verify(contract, proof)

