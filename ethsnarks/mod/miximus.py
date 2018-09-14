__all__ = ('Miximus',)

import os
import re
import ctypes

from ..verifier import Proof, VerifyingKey


class Miximus(object):
    def __init__(self, native_library_path, vk, pk_file=None):
        if pk_file:
            if not os.path.exists(pk_file):
                raise RuntimeError("Proving key file doesnt exist: " + pk_file)
        self._pk_file = pk_file

        if not isinstance(vk, VerifyingKey):
            if isinstance(vk, dict):
                vk = VerifyingKey.from_dict(vk)
            elif os.path.exists(vk):
                vk = VerifyingKey.from_file(vk)
            else:
                vk = VerifyingKey.from_json(vk)
        if not isinstance(vk, VerifyingKey):
            raise TypeError("Invalid vk type")
        self._vk = vk

        lib = ctypes.cdll.LoadLibrary(native_library_path)

        lib_tree_depth = lib.miximus_tree_depth
        lib_tree_depth.restype = ctypes.c_size_t
        self.tree_depth = lib_tree_depth()
        assert self.tree_depth > 0
        assert self.tree_depth < 32

        lib_prove = lib.miximus_prove
        lib_prove.argtypes = ([ctypes.c_char_p] * 6) + [(ctypes.c_char_p * self.tree_depth)]
        lib_prove.restype = ctypes.c_char_p
        self._prove = lib_prove

        lib_verify = lib.miximus_verify
        lib_verify.argtypes = [ctypes.c_char_p, ctypes.c_char_p] 
        lib_verify.restype = ctypes.c_bool
        self._verify = lib_verify

    def prove(self, root, nullifier, spend_preimage, exthash, address_bits, path, pk_file=None):
        assert isinstance(path, (list, tuple))
        assert len(path) == self.tree_depth
        if isinstance(address_bits, (tuple, list)):
            address_bits = ''.join([str(_) for _ in address_bits])
        assert re.match(r'^[01]+$', address_bits)
        assert len(address_bits) == self.tree_depth
        assert isinstance(root, int)
        assert isinstance(nullifier, int)
        assert isinstance(spend_preimage, int)
        assert isinstance(exthash, int)
        # TODO: require root, nullifier, spend_preimage and exthash are ints within curve order range

        if pk_file is None:
            pk_file = self._pk_file
        if pk_file is None:
            raise RuntimeError("No proving key file")

        # Public parameters
        root = ctypes.c_char_p(str(root).encode('ascii'))
        nullifier = ctypes.c_char_p(str(nullifier).encode('ascii'))
        exthash = ctypes.c_char_p(str(exthash).encode('ascii'))
    
        # Private parameters
        spend_preimage = ctypes.c_char_p(str(spend_preimage).encode('ascii'))
        address_bits = ctypes.c_char_p(address_bits.encode('ascii'))
        path = [ctypes.c_char_p(str(_).encode('ascii')) for _ in path]
        path_carr = (ctypes.c_char_p * len(path))()
        path_carr[:] = path

        pk_file_cstr = ctypes.c_char_p(pk_file.encode('ascii'))

        data = self._prove(pk_file_cstr, root, nullifier, exthash, spend_preimage, address_bits, path_carr)
        if data is None:
            raise RuntimeError("Could not prove!")
        return Proof.from_json(data)

    def verify(self, proof):
        if not isinstance(proof, Proof):
            raise TypeError("Invalid proof type")

        vk_cstr = ctypes.c_char_p(self._vk.to_json().encode('ascii'))
        proof_cstr = ctypes.c_char_p(proof.to_json().encode('ascii'))

        return self._verify( vk_cstr, proof_cstr )
