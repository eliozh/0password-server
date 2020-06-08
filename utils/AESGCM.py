#! /usr/bin/python
# -*- coding: utf-8 -*-
"""
@File       :   AESGCM.py
@Time       :   20/06/05 19:08
@Author     :   Elio Zhou
"""

import uuid
import json

from Cryptodome.Cipher import AES
from jwkest.jwk import SYMKey
from typing import Optional, Tuple, Union

from utils.utils import opb64e, generate_key


class AES256GCM:

    def __init__(self, kid: Optional[str] = None):
        if kid is None:
            self.kid = opb64e(uuid.uuid4().bytes)
        else:
            self.kid = kid

        self.k = generate_key(32)

        # generate AESKey
        self.key = SYMKey(alg='A256GCM', kid=self.kid, k=opb64e(self.k))

    def key_serialize(self, return_str: bool = False) -> Union[dict, str]:
        """
        Serialize sym key as JWK format.
        :param return_str:
        :return:
        """
        dict_res = self.key.serialize()

        if return_str:
            return json.dumps(dict_res)
        else:
            return dict_res

    def encrypt(self, text: bytes, iv: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        if iv is None:
            iv = generate_key(12)

        aes = AES.new(self.k, AES.MODE_GCM, iv, mac_len=16)

        cipher_text, tag = aes.encrypt_and_digest(text)

        return iv, cipher_text + tag

    def decrypt(self, cipher_text: bytes, iv: bytes) -> bytes:
        aes = AES.new(self.k, AES.MODE_GCM, iv)

        text = aes.decrypt(cipher_text)

        return text
