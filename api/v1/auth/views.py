#! /usr/bin/python
# -*- coding: utf-8 -*-
"""
@File       :   views.py
@Time       :   20/06/01 13:23
@Author     :   Elio Zhou
"""

import logging
import string
import random
import os

from flask import request, Response, send_file
from flask_restful import Resource
from flask_mail import Message

from settings import BASE_DIR
from common.models import User
from common.database import db
from common.redis import redis_db
from common.serializer import s
from common.mail import mail
from utils.utils import get_random_string
from utils.crypto import generate_password_sqlite, compute_2skd, opb64e
# from utils import crypto
from settings import sync_delay_prefix, verify_send_delay_prefix, verify_token_valid_prefix, SALT


class Register(Resource):
    """
    用户注册
    """

    @staticmethod
    def post():
        try:
            # get first_name, last_name, email and password
            first_name = request.json.get('first_name').strip()
            last_name = request.json.get('last_name').strip()
            email = request.json.get('email').strip().lower()
            password = request.json.get('password')
        except Exception as e:
            logging.info('invalid. ' + str(e))
            return {'message': 'error'}, 500

        # check if any field is none.
        if first_name is None or last_name is None or email is None or password is None:
            logging.info('error.')
            return {'message': 'error'}, 500

        # check if user existed.
        user = User.query.filter_by(email=email).first()
        if user is not None:
            return {'message': 'error'}, 500

        # check if account id existed.
        account_id = get_random_string(6, string.ascii_uppercase + string.digits)
        user = User.query.filter_by(account_id=account_id).first()
        while user is not None:
            account_id = get_random_string(6, string.ascii_uppercase + string.digits)
            user = User.query.filter_by(account_id=account_id).first()

        srp_salt = get_random_string(16, string.ascii_letters + string.digits + string.punctuation)
        password_salt = get_random_string(16, string.ascii_letters + string.digits + string.punctuation)

        version = 'A1'

        password_iterations = random.randint(50000, 100000)
        srp_iterations = random.randint(50000, 100000)

        secret = get_random_string(6, string.ascii_uppercase + string.digits) + '-'
        secret += '-'.join(get_random_string(5, string.ascii_uppercase + string.digits) for _ in range(4))

        secret_key = '-'.join([version, account_id, secret])

        # algorithm SRPg-4096 for SRP-X.
        srp_x = compute_2skd(secret_key, password, email, srp_salt.encode('utf-8'), srp_iterations, 'SRPg-4096')

        srp_x = opb64e(srp_x)

        # generate sqlite file.
        sqlite_path = os.path.join(BASE_DIR, 'tmp', account_id + '.db')

        generate_password_sqlite(secret_key, password, email, first_name, last_name, sqlite_path)

        with open(sqlite_path, 'rb') as f:
            sqlite_data = f.read()

        user = User(
            first_name=first_name,
            last_name=last_name,
            email=email,
            password_salt=password_salt,
            srp_salt=srp_salt,
            srp_x=srp_x,
            srp_iterations=srp_iterations,
            version=version,
            account_id=account_id,
            sqlite_data=sqlite_data
        )

        # add user.
        db.session.add(user)
        db.session.commit()

        if os.path.exists(sqlite_path):
            os.remove(sqlite_path)

        return {'email': email, 'secret_key': secret_key}


class SendVerifyEmail(Resource):
    @staticmethod
    def post():
        # get email.
        try:
            email = request.json.get('email').strip().lower()
            password = request.json.get('email')
            secret_key = request.json.get('secret_key').strip()
        except Exception as e:
            logging.info('' + str(e))
            return {'message': 'error'}, 500

        # check if any field is none.
        if email is None or password is None or secret_key is None:
            return {'message': 'error'}, 500

        # check if user existed or verified.
        user = User.query.filter_by(email=email).first()
        if user is None:
            return {'message': 'error'}, 500

        # check password and secret key.
        srp_x = compute_2skd(secret_key, password, email, user.srp_salt.encode('utf-8'),
                             iterations=user.srp_iterations, algorithm='SRPg-4096')
        if opb64e(srp_x) != user.srp_x:
            return {'message': 'error'}, 500

        # check if user is verified.
        if user.verified:
            return {'message': 'error'}, 500

        # check if email has been sent recently
        delay = redis_db.pttl(verify_send_delay_prefix + email)
        if delay != -2:  # key exists.
            return {'message': 'error'}, 500

        # generate verify code
        verify = get_random_string(6, string.ascii_uppercase + string.digits)
        # generate verify link token
        token = s.dumps({'email': email}, salt=SALT)

        msg = Message(
            subject='0password verify',
            recipients=[email],
            body='verify',
            html=f'<p>verify: {verify}<p>'
        )

        try:
            mail.send(msg)
        except Exception as e:
            logging.info('' + str(e))
            return {'message': 'error'}, 500

        redis_db.set_redis_token(verify_token_valid_prefix + email, token + verify, expire_time=60 * 30)
        redis_db.set_redis_token(verify_send_delay_prefix + email, 1, expire_time=60)

        return {'email': email, 'token': token}


class Verify(Resource):
    @staticmethod
    def post(token):
        # get verify
        try:
            verify = request.json.get('verify').upper()
        except Exception as e:
            logging.info('' + str(e))
            return {'message': 'error'}, 500

        # check if token is valid.
        try:
            data = s.loads(token, salt=SALT)
        except Exception as e:
            logging.info('' + str(e))
            return {'message': 'error'}, 500

        # get saved verify code.
        value = redis_db.get_redis_token(verify_token_valid_prefix + data['email'])
        if value is None:
            return {'message': 'error'}, 500

        # check if it is the lasted token.
        if token != value[:-6]:
            return {'message': 'error'}, 500

        # check verify.
        if verify != value[-6:]:
            return {'message': 'error'}, 500

        # confirm user
        user = User.query.filter_by(email=data['email']).first()
        user.verified = True

        db.session.commit()

        return {'email': data['email'], 'message': 'success'}


class Sync(Resource):

    @staticmethod
    def post(token):
        try:
            # get email, password, secret key
            email = request.json.get('email').strip().lower()
            password = request.json.get('password')
            secret_key = request.json.get('secret_key').strip()
        except Exception as e:
            logging.info('invalid. ' + str(e))
            return {'message': 'error'}, 500

        # check if any field is none.
        if email is None or password is None or secret_key is None:
            logging.info('error.')
            return {'message': 'error'}, 500

        # check if user existed.
        user = User.query.filter_by(email=email).first()
        if user is None:
            return {'message': 'error'}, 500

        # check password and secret key.
        srp_x = compute_2skd(secret_key, password, email, user.srp_salt.encode('utf-8'),
                             iterations=user.srp_iterations, algorithm='SRPg-4096')
        if opb64e(srp_x) != user.srp_x:
            return {'message': 'error'}, 500

        # check if user is verified.
        if not user.verified:
            return {'message': 'error'}, 500

        # check if this account has sync recently.
        delay = redis_db.pttl()
        if delay != -2:  # key exists.
            return {'message': 'error'}, 500

        blob = user.sqlite_data

        redis_db.set_redis_token(sync_delay_prefix + email, 1, expire_time=60 * 5)

        return Response(response=blob, content_type='application/octet-stream')
