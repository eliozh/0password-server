#! /usr/bin/python
# -*- coding: utf-8 -*-
"""
@File       :   cryptp.py
@Time       :   20/06/01 13:53
@Author     :   Elio Zhou
"""

import struct
import re
import hashlib
import random
import uuid
import json
import hmac

from Cryptodome.Protocol.KDF import HKDF
from Cryptodome.Hash import SHA256
from Cryptodome.Cipher import AES
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine

from utils.utils import opb64e, generate_key, bytes_pad
from utils.AESGCM import AES256GCM
from utils.RSACipher import RSACipher
from utils.EncJSON import EncJSON
from common.sqlite import Account, Keysets, VaultAccess, Config, Base


def generate_password_sqlite(sk: str, password: str, email: str, first_name: str, last_name: str, sqlite_path: str):
    account_id = sk.split('-')[1]
    engine = create_engine(f'sqlite:///{sqlite_path}')
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)

    session = Session()

    # generate emk with password.
    enc_hmac_together = generate_key(64)
    emk = generate_emk(enc_hmac_together, password.encode('utf-8'))

    # generate enc_login with email, password, secret-key.
    pt = json.dumps({'accountKey': sk, 'password': password})
    enc_login = generate_opdata(pt.encode('utf-8'), enc_hmac_together[:32], enc_hmac_together[32:])

    # generate muk with sk, password, email.
    p2salt = generate_key(16)
    p2c = 100000
    alg = 'PBES2g-HS256'
    muk = compute_2skd(sk, password, email, p2salt, p2c, alg)

    # generate first item of keysets.
    first_keyset_kid = opb64e(uuid.uuid4().bytes).decode('utf-8')
    iv = generate_key(12)
    sym_key = AES256GCM(kid=first_keyset_kid)
    rsa_key = RSACipher(kid=first_keyset_kid)

    mp = AES.new(muk, AES.MODE_GCM, iv, mac_len=16)
    ct, tag = mp.encrypt_and_digest(sym_key.key_serialize(return_str=True).encode('utf-8'))
    enc_sym_key_data = opb64e(ct + tag).decode('utf-8')
    enc_sym_key = EncJSON(enc='A256GCM', kid='mp', data=enc_sym_key_data, iv=opb64e(iv).decode('utf-8'),
                          alg='PBES2g-HS256', p2s=opb64e(p2salt).decode('utf-8'), p2c=p2c)

    iv, ct = sym_key.encrypt(rsa_key.key_serialize(private=True, return_str=True).encode('utf-8'))
    enc_pri_key = EncJSON(enc=sym_key.key.alg, kid=sym_key.kid, data=opb64e(ct).decode('utf-8'),
                          iv=opb64e(iv).decode('utf-8'))

    # TODO: enc_vault_access
    vault_access_key = AES256GCM()
    enc_vault_key_data = opb64e(
        rsa_key.encrypt(vault_access_key.key_serialize(return_str=True).encode('utf-8'))).decode('utf-8')
    enc_vault_key = EncJSON(enc=rsa_key.key.alg, kid=rsa_key.kid, data=enc_vault_key_data)

    keyset = Keysets(
        enc_pri_key=enc_pri_key.serialize(return_str=True),
        enc_sym_key=enc_sym_key.serialize(return_str=True),
        pub_key=sym_key.key_serialize(return_str=True),
        encrypted_by='mp',
        uuid=first_keyset_kid
    )

    vault_access_key = VaultAccess(enc_vault_key=enc_vault_key.serialize(return_str=True))

    account = Account(
        email=email,
        enc_login=opb64e(enc_login).decode('utf-8'),
        first_name=first_name,
        last_name=last_name
    )

    config = Config(name='EncryptedMasterKey', value=opb64e(emk).decode('utf-8'))

    session.add_all([keyset, vault_access_key, account, config])

    session.commit()


def generate_opdata(pt: bytes, enc_key: bytes, hmac_key: bytes) -> bytes:
    header = b'opdata01'

    pt_length = struct.pack('<Q', len(pt))

    pt = generate_key(16) + bytes_pad(pt, padding=16)

    iv = generate_key(16)

    c = AES.new(enc_key, AES.MODE_CBC, iv=iv)
    ct = c.encrypt(pt)

    opdata = header + pt_length + iv + ct

    hm = hmac.new(hmac_key, msg=opdata, digestmod=hashlib.sha256).digest()

    return opdata + hm


def generate_emk(pt: bytes, password: bytes) -> bytes:
    iterations = random.randint(5000, 12000)

    salt = generate_key(16)

    salt_len = struct.pack('<I', 16)

    raw_key = hashlib.pbkdf2_hmac('sha512', password, salt, iterations, dklen=64)

    emk_enc_key = raw_key[0:32]
    emk_hmac_key = raw_key[32:64]

    opdata = generate_opdata(pt, emk_enc_key, emk_hmac_key)

    payload_len = struct.pack('<I', len(opdata))

    iterations = struct.pack('<I', iterations)

    emk = iterations + salt_len + salt + payload_len + opdata

    return emk


def compute_2skd(sk: str, password: str, email: str, p2salt: bytes, iterations: int, algorithm: str):
    version = sk[0:2]
    account_id = sk[3:9]
    secret = re.sub('-', '', sk[10:])
    email = email.lower()

    email = email.encode('utf-8')
    version = version.encode('utf-8')
    secret = secret.encode('utf-8')
    account_id = account_id.encode('utf-8')
    algorithm = algorithm.encode('utf-8')

    hkdf_pass_salt = HKDF(p2salt, 32, email, SHA256, 1, algorithm)

    password = password.encode('utf-8')

    password_key = hashlib.pbkdf2_hmac('sha256', password, hkdf_pass_salt, iterations, dklen=32)

    hkdf_key = HKDF(secret, 32, account_id, SHA256, 1, version)

    final_key = []

    for i in range(32):
        a = password_key[i]
        b = hkdf_key[i]
        c = a ^ b
        final_key.append(c)

    return bytes(final_key)
