#! /usr/bin/python
# -*- coding: utf-8 -*-
"""
@File       :   serializer.py
@Time       :   20/06/01 14:27
@Author     :   Elio Zhou
"""

from itsdangerous import URLSafeTimedSerializer

from settings import SECRET_KEY, SALT

s = URLSafeTimedSerializer(SECRET_KEY, SALT)
