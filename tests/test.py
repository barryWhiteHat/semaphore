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

if __name__ == "__main__":

    pk_output = "../zksnark_element/pk.raw"
    vk_output = "../zksnark_element/vk.json"

    genKeys(c.c_int(tree_depth), c.c_char_p(pk_output.encode()) , c.c_char_p(vk_output.encode())) 
    nullifiers = []
    sks = []
    leaves = []
    fee = 0 

    for j in range (0,2):
        nullifiers.append("0x" + genSalt(64)) 
        sks.append("0x" + genSalt(64))
        signal = ("0x" + genSalt(64))
        signal_variables = ("0x" + genSalt(64))
        external_nullifier = ("0x" + genSalt(64))
        leaves.append(utils.hashPadded(nullifiers[j], sks[j]))
    
    for address, (nullifier , sk) in enumerate(zip(nullifiers, sks)):

        proof, root = genWitness(leaves, nullifier, sk, signal , signal_variables, external_nullifier, address, tree_depth, fee, "../zksnark_element/pk.raw", True)              
        isTrue = checkProof("../zksnark_element/vk.raw", proof)
        output = utils.libsnark2python(proof["input"])
        try:
            assert(isTrue)
            assert(output[0] == root)
            assert(output[1] == signal) 
            assert(output[2] == signal_variables)
            assert(output[3] == external_nullifier)
            assert(utils.hashPadded(nullifier, output[3]) == output[4])
        except:
            pdb.set_trace()

        print(isTrue)
