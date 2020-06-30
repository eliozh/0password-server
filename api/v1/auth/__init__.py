#! /usr/bin/python
# -*- coding: utf-8 -*-
"""
@File       :   __init__.py
@Time       :   20/06/01 13:23
@Author     :   Elio Zhou
"""

from api.v1.auth.views import Register, SendVerifyEmail, Verify, Sync, Index, Upload


def init_api(api):
    api.add_resource(Index, '/index')

    api.add_resource(Register, '/auth/register')

    api.add_resource(SendVerifyEmail, '/auth/send-verify-email')

    api.add_resource(Verify, '/auth/verify/<token>')

    api.add_resource(Sync, '/auth/sync')

    api.add_resource(Upload, '/auth/upload')
