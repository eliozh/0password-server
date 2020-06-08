#! /usr/bin/python
# -*- coding: utf-8 -*-
"""
@File       :   models.py
@Time       :   20/05/31 23:08
@Author     :   Elio Zhou
"""

from common.database import db


class User(db.Model):

    # user id
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)

    # name
    first_name = db.Column(db.String(length=20))
    last_name = db.Column(db.String(length=20))

    # email
    email = db.Column(db.String(length=80), unique=True)

    # auth related
    password_salt = db.Column(db.String(length=10))  # used for generate muk
    srp_salt = db.Column(db.String(length=10))
    srp_x = db.Column(db.String(length=32))
    srp_iterations = db.Column(db.Integer)

    # serial number
    # version
    version = db.Column(db.String(length=2))
    account_id = db.Column(db.String(length=6), unique=True)

    verified = db.Column(db.Boolean, default=False)

    sqlite_data = db.Column(db.BLOB())

    created_at = db.Column(db.Integer)
    last_auth_at = db.Column(db.Integer)
