import unittest
import json
import time
import random

from ethsnarks.verifier import VerifyingKey, Proof
from ethsnarks.deploy import genWitness, tree_depth, verify
from ethsnarks.helpers import initMerkleTree
from ethsnarks.utils import genMerkelTree, sha256


VK_FILENAME = 'zksnark_element/vk.json'
PK_FILENAME = 'zksnark_element/pk.json'

VK_STATIC = {
 "a" :[["0xd5aabf07943df51a3bb40b84a4379291cbec540ff959a1f5b23630a0012e8f2", "0x686b4f193e8bd85536d66ca633239cc3dab8c4e844bc9d56f00ab1e09ac3f0f"],
 ["0x37f2d1923fdf5bf7785b0507c057eeead629cbd82c6fde255024ac027e64680", "0x11e2c6bbdc9b607f2b2553a2a36dc5a9341e26634bb534a995d6d8ec0fa5e0e7"]],
 "b"  :["0x2c3fd900b63b90ecc28b0253df7682d8cb7fbfce58aba8a4aeea326ed484223f", "0x5280a3750a775f5f84afad63c775ce98c3dbfa13936c89afb030eb5cbc2b55c"],
 "c" :[["0x2f1b632907021f8cf56d0ad375e2bdf70217e93be3c8c447ec165e0e46c10d68", "0x16981857d333c91cf173c18a61b62640787de53230c3d6949aec64b7312f28d9"],
 ["0x2fff0dd4da12a1d21bae444f7ccd2560b6980af5586175d7ae6c9fb3660eb4ec", "0x127385a87c42398978968803128d2806c01dabc4abf8cf567e977ca00cec0943"]],
 "g" :[["0x10595fc5f30cf48014d3f690782ad81905b4573105475672d338a3baf86c1c08", "0xf8f8e0c572526749cc4bef29dafc58d6b975ededa432cb948875b4455d1a7db"],
 ["0x29be0438ae67294717ce504598c57a08db7de217df8864681fe3e657d9ce1589", "0x1a5ce34d5c966b31dfdfcc6ff90e3ab81233f3e1ab2473ba30a936b45a05624a"]],
 "gb1" :["0xe69f76af51fe182975c0c983013847ee5b1a4e5f59f6309a00854d859f7da49", "0x239c3482994b1c21bc694c1b3bc919665d59b48619c141f2426d88bf27627901"],
 "gb2" :[["0x27cfbc023622310dfe2a332334fac890cd0d7cb03bcec61c9c3ef0ec03cb1ed8", "0x11b5ae7b4a358737d6162f9f971e8ada82da1b56c4bcf3e4d946c314ca7938f4"],
 ["0x13d1a4c915ea951e513e57a31c2670943c8e0c0ba66493cfe5a03fd016f7cd3c", "0xb52d1f6b58651a850e9eebbe37fcd61e6a9a1e19d2c4bedd07776ab8da3bd3b"]],
 "z" :[["0x350d53e6025cd2fcd2eb167ba6ade709e7b9b48f57cd4e82e88c6f4174264e", "0x1f741e145ddf8ce94eeb00fa502fcca7615e5649f0f164c95b7d6200c1fc70a9"],
 ["0x2541fb3ae7431251b621adff5199639b09aaac175130b6f66251ae4445fd0b78", "0x14719ef8f2338fd9918c46a091e3e6b741433755a40ecfea24c6f47dd6200e0a"]],
"IC" :[["0x9e0bf745eb5ef0ab11be81dec06e4fead09ff07402f4d77c313b0c217bacc39", "0x10e5fdc30543c43a9fb47bce99d4e494e238ec1851d2a3007b18ca0549056418"],
       ["0x2ee4b7d909cd96ef6f5b3e5bff6e655deba6c88fedc5fb06b9edf864f17e708c", "0xfe21fb8464f666141d0be3e6e80fdbeaacc7010df846750ea76cb0ae151e857"],
       ["0xbbf8fc5c5264a6f171d6a8b1b510cf69fafb54b098e76ecc615344e7f75346e", "0xfaf513a267f926cd5f7857b07766f2509f7c976b3264c981536bea48bd77335"],
       ["0x14e3654e589493a28331a3c60afbe642f986de55411dd17f28cb8ca71bd65fea", "0x6549e53bac6293104e920c735b19af48db9c0097c46511b97efd65a05cb9d37"],
       ["0xf57163576eaa2ecb4fec3733b8333a72e355b90afc0765b357c14bd3e1ad0c2", "0x1a0eb5ba721f60065d55438c04955bc0f43c25f150655f7ec2ee78b68404a43c"],
       ["0x149ec58a7602a0885f6c24315ab2ddb5b61352fb4ba96c9b5913eac2d2207f08", "0x19e622d07d4e7662eaf952dda0672bd6b168f8baf6f4bc2cb14eb4777d919584"],
       ["0x19501f3db91e77513a194e625b3eee6b6899ee84b5511b67296954bd21700ff1", "0x2e97e0dda09d9288a18cb619f9ec3c050c7ee173b89d07524ccc486c0a3935b4"]]}

PROOF_STATIC = {
    'a': ['0x2f6730bdfc1ce5f9ac392ddf2b5d3b67119d2b140869e237b5ab98067e55978e', '0x27ac720824a9a8ec11de5558fe3535cfdbc2320feb5077f0425ed752834142e'],
    'a_p': ['0x1f3ea5c8296bc245569dc9a1fba4b54d7b81755af250d2031174ca418494507a', '0xf147733522ece9fbf57ebffca5266bb8433c8ea190ecc8706af62e2be8b4b58'],
    'b': [['0xc2ad46ff5234a2aa4f4c3dafc9fd1651e0fcd5d78aac497eed0751f678e3221', '0x178df5f36aed1ea133bb3486a6b142554173b4bab122f6e43f08bb9db06cc56d'], ['0x23a44b38c0309ec1b491a829552b76b8420f823b9325687d416f50491cbf0088', '0x251dda2f3ed637188ca66699b670e32a653e7fb41de98d139c64118fa0c21e60']],
    'b_p': ['0x150d816eed12c95698597297023db078c314c4ad5364f901ecb2de326d60131f', '0x95500438e146b731c4a13ff06600a80cce293c5e9990d982002e0b8be9bd890'],
    'c': ['0x2905449d7f142211ea8e521d0f5367e3cd554648e82c29ca937ad1c26adf4b72', '0x6b19af50b9d191f1fcea0ebead96b6c1abf938b4f0c84c348a9370b9a68f2f9'],
    'c_p': ['0x2ccd23a3a1935a0872fd0e58172ee7f4425b474cf220f92cfdf02c32e751fa41', '0x476bd24475524ced86c5baefc8159ea0de54a5061f5adad8e7eb68144e2f51c'],
    'h': ['0x27e9f8c9b59d0e6e3cc2d3191c5e98064039a220be15acb09a96a66ed7339781', '0x24b14ee857ba8725d9d936aa4ddb12d6119c309c298d906ad25f2713ac197574'],
    'k': ['0xd84eb9d58760476464a6ee388b695b7e8fde533a0bb6e3da7ad79cccff44d4b', '0x1f8b4dc8359127d69b789b948b0ce96164a83ac2b34ae50191a0e056c49914f'],
    'input': ['0x1485e320178a702065363b045ed3b43d4d30f63df0f318a8c2b85f083a2dc540', '0x328e91687fbf4d28afd872da677f8af2eb8a3ec972e00f9e66d6f59cc58510e', '0x16b87b6ed29e00e4ae3d1155c96d78babf16bfdc8075ae61cfcb3ff39358759e', '0x195d4bb987d2fada8ae0327237e830b053d508ed62c8edc270c89e631bdc57a5', '0xa475d3c450a6f8185beb0ec1964cb0fad03a69daa163cab96f382fe8ffdb861', '0x5d43']}


class VerifyTests(unittest.TestCase):
    def test_vk_roundtrip(self):
        vk = VerifyingKey.from_dict(VK_STATIC)
        vk_json = vk.to_json()
        vk2 = VerifyingKey.from_dict(json.loads(vk_json))
        self.assertEqual(vk, vk2)

    def test_verify_native(self):
        vk = VerifyingKey.from_dict(VK_STATIC)
        proof = Proof.from_dict(PROOF_STATIC)
        self.assertTrue(verify(vk.to_json(), proof.to_json()))

    """
    def test_verify_python(self):
        # Static test data for proof verification
        
        proof = Proof.from_dict(proof_data)
        vk = VerifyingKey.from_dict(VK_STATIC)
        vk.verify(proof)
    """

    #"""
    def test_proof_gen(self):
        leaves, nullifiers, sks = initMerkleTree(2) 
        root, layers = genMerkelTree(tree_depth, leaves)
        signal_variables = sha256(str(1))
        external_nullifier = sha256("nomimatedSpokesPerson"+root+str(time.time()))
        signal1 = sha256({"NomimatedSpokesPersonFor":root , "candidate": "Candidate1" })
        proof = None

        with open('zksnark_element/vk.json', 'r') as handle:
            vk = VerifyingKey.from_dict(json.load(handle))

        for address, (nullifier , sk) in enumerate(zip(nullifiers, sks)):
            rand = int(random.uniform(1, 3)) 
            print("Generating witness")
            proof_data, proof_root = genWitness(leaves, nullifier, sk, signal1 , signal_variables, external_nullifier, address, tree_depth, 0, PK_FILENAME)
            proof = Proof.from_dict(proof_data)
            print("Proof:", proof)
            self.assertTrue(verify(vk.to_json(), proof.to_json()))
            with open('zksnark_element/proof.json', 'w') as handle:
                handle.write(proof.to_json())
            break
    #"""

if __name__ == "__main__":
    unittest.main()
