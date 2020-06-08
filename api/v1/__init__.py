#! /usr/bin/python
# -*- coding: utf-8 -*-
"""
@File       :   __init__.py
@Time       :   20/06/01 13:23
@Author     :   Elio Zhou
"""

from flask_restful import Api

from api.v1.auth import init_api as auth_init_api


def create_api():
    api = Api(prefix='/api/v1/')
    auth_init_api(api)

    return api
