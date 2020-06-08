#! /usr/bin/python
# -*- coding: utf-8 -*-
"""
@File       :   utils.py
@Time       :   20/06/01 13:33
@Author     :   Elio Zhou
"""

import string
import time
import hashlib
import random
import base64
import binascii

from Crypto import Random
from typing import Union

# Use the system PRNG if possible
try:
    random = random.SystemRandom()
    using_sysrandom = True
except NotImplementedError:
    import warnings

    warnings.warn('A secure pseudo-random number generator is not available '
                  'on your system. Falling back to Mersenne Twister.')
    using_sysrandom = False


def get_random_secret_key(length=50):
    """
    Return a 50 character random string usable as a SECRET_KEY setting value.
    """
    chars = 'abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*(-_=+)'
    return get_random_string(length, chars)


def get_random_string(length=12, allowed_chars='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'):
    """
    Returns a securely generated random string.

    The default length of 12 with the a-z, A-Z, 0-9 character set returns
    a 71-bit value. log_2((26+26+10)^12) =~ 71 bits
    """
    if not using_sysrandom:
        # This is ugly, and a hack, but it makes things better than
        # the alternative of predictability. This re-seeds the PRNG
        # using a value that is hard for an attacker to predict, every
        # time a random string is required. This may change the
        # properties of the chosen random sequence slightly, but this
        # is better than absolute predictability.
        random.seed(hashlib.sha256(("%s%s" % (random.getstate(), time.time())).encode('utf-8')).digest())
    return ''.join(random.choice(allowed_chars) for i in range(length))


def format_hex(i: int) -> bytes:
    r = hex(i)[2:]
    if len(r) % 2 != 0:
        r = '0' + r
    return bytes.fromhex(r)


def opb64e(dat: bytes) -> bytes:
    return base64.urlsafe_b64encode(dat)


def opb64d(b64dat: Union[str, bytes]) -> bytes:
    pad = object()

    if isinstance(b64dat, str):
        pad = '='
    elif isinstance(b64dat, bytes):
        pad = b'='

    try:
        out = base64.urlsafe_b64decode(b64dat)
    except binascii.Error:
        try:
            out = base64.urlsafe_b64decode(b64dat + pad)
        except binascii.Error:
            out = base64.urlsafe_b64decode(b64dat + pad * 2)

    return out


def generate_key(length: int = 32) -> bytes:
    return Random.new().read(length)


def bytes_pad(text: bytes, padding: int = 16) -> bytes:
    if len(text) % padding == 0:
        return text

    pad = generate_key(padding - (len(text) % padding))

    return pad + text
