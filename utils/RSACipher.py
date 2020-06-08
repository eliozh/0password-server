#! /usr/bin/python
# -*- coding: utf-8 -*-
"""
@File       :   RSACipher.py
@Time       :   20/06/05 17:38
@Author     :   Elio Zhou
"""

import uuid
import json

from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from jwkest.jwk import RSAKey
from typing import Optional, Union

from utils.utils import opb64e
from utils.utils import format_hex


class RSACipher:

    def __init__(self, kid: Optional[str] = None):
        if kid is None:
            self.kid = opb64e(uuid.uuid4().bytes)
        else:
            self.kid = kid

        random_generator = Random.new().read
        rsa = RSA.generate(2048, random_generator)

        self.pri = rsa
        self.pub = rsa.publickey()

        # generate RSAKey.
        attr_names = ['n', 'e', 'd', 'p', 'q']
        attr_values = [getattr(self.pri, attr_name) for attr_name in attr_names if hasattr(self.pri, attr_name)]

        # base64
        attr_values = list(map(lambda i: opb64e(format_hex(i)), attr_values))

        self.key = RSAKey(alg='RSA-OAEP', kid=self.kid, **dict(zip(attr_names, attr_values)))

    def key_serialize(self, private: bool, return_str: bool = False) -> Union[dict, str]:
        """
        Serialize rsa private key or public key as JWK format.
        """
        dict_res = self.key.serialize(private=private)

        if return_str:
            return json.dumps(dict_res)
        else:
            return dict_res

    def encrypt(self, text: bytes) -> bytes:
        cipher = PKCS1_OAEP.new(self.pub)

        cipher_text = cipher.encrypt(text)

        return cipher_text

    def decrypt(self, cipher_text: bytes) -> bytes:
        cipher = PKCS1_OAEP.new(self.pri)

        text = cipher.decrypt(cipher_text, 'ERROR')

        return text
