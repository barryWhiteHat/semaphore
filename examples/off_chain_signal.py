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

import sys
sys.path.insert(0, '../snarkWrapper')
from deploy import *
from helpers import initMerkleTree
from utils import genMerkelTree, sha256
import hashlib
import time
import random


if __name__ == "__main__":

    pk_output = "../zksnark_element/pk.raw"
    vk_output = "../zksnark_element/vk.json"

    # perform the trusted setup making hte proving key ,  verification key
    genKeys(c.c_int(tree_depth), c.c_char_p(pk_output.encode()) , c.c_char_p(vk_output.encode()))


    #part 1 merkel tree setup which act as the census of the vote
    #make merkel Tree with 10 members
    #This is a trusted part but it can be varified by the users before teh 
    
    leaves, nullifiers, sks = initMerkleTree(5) 
    root, layers = genMerkelTree(29, leaves) 

    #part 2 definition of the vote properties.
    # You "sign" signal 1 to vote for canditate 1
    signal1 = sha256({"NomimatedSpokesPersonFor":root , "candidate": "Candidate1" })
    # You "sign" signal 2 to vote for candidate 2
    signal2 = sha256({"NomimatedSpokesPersonFor":root , "candidate": "Candidate2" })
    # You use external_nullifier to enforce one person (merkle tree memeber) one vote
    external_nullifier = sha256("nomimatedSpokesPerson"+root+str(time.time()))
    # We use signal_variables as a nonce so that you can update your vote.
    # But we do not implment this logic when counting votes as it makes to flow a little complicated
    signal_variables = sha256(str(1))


    # Here we do the actual voteing 
    proofs = []
    for address, (nullifier , sk) in enumerate(zip(nullifiers, sks)):
        rand = int(random.uniform(1, 3)) 
        # randomly select the signal
        if rand == 1:
            signal = signal1
        else:
            signal = signal2
        proof, root = genWitness(leaves, nullifier, sk, signal , signal_variables, external_nullifier, address, tree_depth, 0, "../zksnark_element/pk.raw", True)
        proofs.append(proof)


    signal1_count = 0
    signal2_count = 0 
    for proof in proofs:
        isTrue = checkProof("../zksnark_element/vk.raw", proof)
        output = utils.libsnark2python(proof["input"])
        # Check the proof is correct
        assert(isTrue)
        # Check it is for our merkle root
        assert(output[0] == root)
        # Check that we used the correct nullifier
        assert(output[3] == external_nullifier)
        # Get the signal 
        signal = output[1]

        # Count the signals for candidate1 and 2

        if( signal == signal1):
            signal1_count = signal1_count + 1
        if (signal == signal2):
            signal2_count = signal2_count + 1
        # Here we could add logic to allow updating votes by tracking the output[4] which is the users nullifier
        # hashed with the external nullifer. It is uiquie to each user and is unchnageable. So we can track their priuos 
        # vote and update it when the current vote is provided. 
        assert(output[2] == signal_variables)
    print("results candidate 1 " + str(signal1_count) + " candidate 2 " + str(signal2_count))
