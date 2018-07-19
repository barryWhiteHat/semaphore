import unittest
import json
import time
import random

from ethsnarks.verifier import VerifyingKey, Proof
from ethsnarks.deploy import genWitness, tree_depth
from ethsnarks.helpers import initMerkleTree
from ethsnarks.utils import genMerkelTree, sha256


VK_FILENAME = 'zksnark_element/vk.json'

VK_STATIC = {
 "a" :[["0xd5aabf07943df51a3bb40b84a4379291cbec540ff959a1f5b23630a0012e8f2", "0x686b4f193e8bd85536d66ca633239cc3dab8c4e844bc9d56f00ab1e09ac3f0f"],
 ["0x37f2d1923fdf5bf7785b0507c057eeead629cbd82c6fde255024ac027e64680", "0x11e2c6bbdc9b607f2b2553a2a36dc5a9341e26634bb534a995d6d8ec0fa5e0e7"]],
 "b"  :["2c3fd900b63b90ecc28b0253df7682d8cb7fbfce58aba8a4aeea326ed484223f", "0x5280a3750a775f5f84afad63c775ce98c3dbfa13936c89afb030eb5cbc2b55c"],
 "c" :[["0x2f1b632907021f8cf56d0ad375e2bdf70217e93be3c8c447ec165e0e46c10d68", "0x16981857d333c91cf173c18a61b62640787de53230c3d6949aec64b7312f28d9"],
 ["0x2fff0dd4da12a1d21bae444f7ccd2560b6980af5586175d7ae6c9fb3660eb4ec", "0x127385a87c42398978968803128d2806c01dabc4abf8cf567e977ca00cec0943"]],
 "g" :[["0x10595fc5f30cf48014d3f690782ad81905b4573105475672d338a3baf86c1c08", "0xf8f8e0c572526749cc4bef29dafc58d6b975ededa432cb948875b4455d1a7db"],
 ["0x29be0438ae67294717ce504598c57a08db7de217df8864681fe3e657d9ce1589", "0x1a5ce34d5c966b31dfdfcc6ff90e3ab81233f3e1ab2473ba30a936b45a05624a"]],
 "gb1" :["e69f76af51fe182975c0c983013847ee5b1a4e5f59f6309a00854d859f7da49", "0x239c3482994b1c21bc694c1b3bc919665d59b48619c141f2426d88bf27627901"],
 "gb2" :[["0x27cfbc023622310dfe2a332334fac890cd0d7cb03bcec61c9c3ef0ec03cb1ed8", "0x11b5ae7b4a358737d6162f9f971e8ada82da1b56c4bcf3e4d946c314ca7938f4"],
 ["0x13d1a4c915ea951e513e57a31c2670943c8e0c0ba66493cfe5a03fd016f7cd3c", "0xb52d1f6b58651a850e9eebbe37fcd61e6a9a1e19d2c4bedd07776ab8da3bd3b"]],
 "z" :[["0x350d53e6025cd2fcd2eb167ba6ade709e7b9b48f57cd4e82e88c6f4174264e", "0x1f741e145ddf8ce94eeb00fa502fcca7615e5649f0f164c95b7d6200c1fc70a9"],
 ["0x2541fb3ae7431251b621adff5199639b09aaac175130b6f66251ae4445fd0b78", "0x14719ef8f2338fd9918c46a091e3e6b741433755a40ecfea24c6f47dd6200e0a"]],
"IC" :[["9e0bf745eb5ef0ab11be81dec06e4fead09ff07402f4d77c313b0c217bacc39", "0x10e5fdc30543c43a9fb47bce99d4e494e238ec1851d2a3007b18ca0549056418"],
       ["2ee4b7d909cd96ef6f5b3e5bff6e655deba6c88fedc5fb06b9edf864f17e708c", "0xfe21fb8464f666141d0be3e6e80fdbeaacc7010df846750ea76cb0ae151e857"],
       ["bbf8fc5c5264a6f171d6a8b1b510cf69fafb54b098e76ecc615344e7f75346e", "0xfaf513a267f926cd5f7857b07766f2509f7c976b3264c981536bea48bd77335"],
       ["14e3654e589493a28331a3c60afbe642f986de55411dd17f28cb8ca71bd65fea", "0x6549e53bac6293104e920c735b19af48db9c0097c46511b97efd65a05cb9d37"],
       ["f57163576eaa2ecb4fec3733b8333a72e355b90afc0765b357c14bd3e1ad0c2", "0x1a0eb5ba721f60065d55438c04955bc0f43c25f150655f7ec2ee78b68404a43c"],
       ["149ec58a7602a0885f6c24315ab2ddb5b61352fb4ba96c9b5913eac2d2207f08", "0x19e622d07d4e7662eaf952dda0672bd6b168f8baf6f4bc2cb14eb4777d919584"],
       ["19501f3db91e77513a194e625b3eee6b6899ee84b5511b67296954bd21700ff1", "0x2e97e0dda09d9288a18cb619f9ec3c050c7ee173b89d07524ccc486c0a3935b4"]]}


class VerifyTests(unittest.TestCase):
    def test_load(self):
        vk = VerifyingKey.from_dict(VK_STATIC)

    """
    def test_verify_python(self):
        # Static test data for proof verification
        proof_data = {
            'a': ['0x24e3d8b04fa4ed3468b15d11280ce81f1098fc030df1b0768f61ec64be738408', '0x18cda07ef41905ff8a88dfaf8fd2a481ef3932670b910b4153debbdbd0031214'],
            'a_p': ['0x12f3a0d408e7ea33a6b4ad37608b66e3bd29a96e7f9b3f23116a1adaa89a3161', '0x8a616e34861a6599266f1bd04e63150197a87b018bf72bcb73af8e9fc79b5cc'],
            'b': [['0x12064588c47341bef01fb0922d62892b5d94eb34464cc38b482079b6222dfdb1', '0x2cf704ab134fd4617ba049928a11d5b49ef9d4c1e30ba7c9ac730ff58d16d900'],
                  ['0x471b185a91c876f070fa2626f3f37b87e390f6f4a11f184edfcf0186d410575', '0x7fd4ec7c99717df309bbfe50c6985b021d7c6a03b0d72a476d33bad0c24a9ea']],
            'b_p': ['0x7aa9a7d19085d9d796916da749ca6e28e1bc8c45335fe75d422e4e5436c94aa', '0xe2df2ea2923a5733399917e222048bcb9284f4f4da5ca3cd91c6e3c47f6d441'],
            'c': ['0x111e88880c84a123f724270640fbef90614d381b9141a241abb8a36b03bdbbb0', '0xe9afeeaaf58e11ffe1e0020583d894333e37c0802f3a73e2fe9691200d2d696'],
            'c_p': ['0x1e98b69df00aa0943e36ac36e57df51043734ea9403e464a22ad60ae143e28da', '0x26826525b5e2603eb0332019822bd5d2cee7ee4f6d03e05badbeab6ea0ff1009'],
            'h': ['0x907054e0c2277f41adb3f0475eacb74bec3419dd9748decd63839cdda793e96', '0xefb38c93e8dca92021ea620f7ad3689a340c4bb6f9aa42190dc9b283715ca94'],
            'k': ['0x20912f9675ce36fb66bbfc25f3923223f4668a9f62ee9ade4cd7250bfdf6cc26', '0x28a5e7ceebf19dd74dc8e58711e391661550d73f1af98dcac61b382d2eca7ac3'],
            'input': ['0x28972182b2c13f42d783f4f744d0f00956b3fe90263a2e128c1f065ba66d856',
                      '0x1dd11492ec8db3265896cc0009938f40c1bc04a1489264bb6cd360a56d0fc1be',
                      '0x16b87b6ed29e00e4ae3d1155c96d78babf16bfdc8075ae61cfcb3ff393587591',
                      '0x9bfd29d7ee17b810b2bdc464d7a34b85f19299e889e5396476cf5594815b1a5',
                      '0x62c7dff2816598f84b9d94569a0987a8dc62fe8366ec22218eabce48ca3156e',
                      '0x2e91']
            }
        proof = Proof.from_dict(proof_data)
        vk = VerifyingKey.from_dict(VK_STATIC)
        vk.verify(proof)
    """

    #"""
    def test_proof_gen(self):
        pk_output = "zksnark_element/pk.raw"
        leaves, nullifiers, sks = initMerkleTree(2) 
        root, layers = genMerkelTree(tree_depth, leaves)
        signal_variables = sha256(str(1))
        external_nullifier = sha256("nomimatedSpokesPerson"+root+str(time.time()))
        signal1 = sha256({"NomimatedSpokesPersonFor":root , "candidate": "Candidate1" })
        proof = None
        for address, (nullifier , sk) in enumerate(zip(nullifiers, sks)):
            rand = int(random.uniform(1, 3)) 
            print("Generating witness")
            proof_data, proof_root = genWitness(leaves, nullifier, sk, signal1 , signal_variables, external_nullifier, address, tree_depth, 0, pk_output)
            proof = Proof.from_dict(proof_data)
            print("Proof:", proof)
            break
    #"""

if __name__ == "__main__":
    unittest.main()
