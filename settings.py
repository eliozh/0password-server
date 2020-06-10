#! /usr/bin/python
# -*- coding: utf-8 -*-
"""
@File       :   settings.py
@Time       :   20/05/31 22:58
@Author     :   Elio Zhou
"""

import os

BASE_DIR = os.getcwd()

# Secret key
SECRET_KEY = '579g^-1qjqdi=673g9tn$5s5@ojif8&w59rr*jn+b#%dx!-_=#'
SALT = 'a%x0xb*1g!xy+^h7y@g@'

# Redis
REDIS_HOST = '127.0.0.1'
REDIS_PORT = 6379
REDIS_PASSWORD = ''
DEFAULT_REDIS_EXPIRE_TIME = 3600

# database setting
# dev db
SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(BASE_DIR, 'test.db')
SQLALCHEMY_TRACK_MODIFICATIONS = True

# redis token prefix
verify_token_valid_prefix = 'VERIFY_TOKEN_VALID_'
verify_send_delay_prefix = 'VERIFY_SEND_DELAY_'
sync_delay_prefix = 'SYNC_DELAY_'

# email
MAIL_SERVER = 'smtp.163.com'
MAIL_PORT = 465
MAIL_USE_SSL = True
MAIL_USE_TLS = False
MAIL_USERNAME = 'z1nyff@163.com'
MAIL_PASSWORD = 'IJVSRBJVVIINYNHC'
MAIL_DEFAULT_SENDER = 'z1nyff@163.com'
