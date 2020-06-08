#! /usr/bin/python
# -*- coding: utf-8 -*-
"""
@File       :   redis.py
@Time       :   20/05/31 23:06
@Author     :   Elio Zhou
"""

import redis

from settings import REDIS_HOST, REDIS_PORT, REDIS_PASSWORD, DEFAULT_REDIS_EXPIRE_TIME


class RedisDb:

    def __init__(self, host, port, password):
        self.redis = redis.Redis(host=host, port=port, password=password, decode_responses=True)

    def set_redis_token(self, key, value, expire_time=DEFAULT_REDIS_EXPIRE_TIME):
        self.redis.set(key, value, ex=expire_time)

    def get_redis_token(self, key):
        if self.redis.exists(key):
            return self.redis.get(key)
        else:
            return None

    def pttl(self, key):
        return self.redis.pttl(key)


redis_db = RedisDb(REDIS_HOST, REDIS_PORT, REDIS_PASSWORD)
