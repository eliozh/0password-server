#! /usr/bin/python
# -*- coding: utf-8 -*-
"""
@File       :   __init__.py
@Time       :   20/06/01 13:23
@Author     :   Elio Zhou
"""

from api.v1 import create_api


def init_api(app):
    api = create_api()

    api.init_app(app)
