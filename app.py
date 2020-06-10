#! /usr/bin/python
# -*- coding: utf-8 -*-
"""
@File       :   app.py
@Time       :   20/06/01 15:15
@Author     :   Elio Zhou
"""

import os

from flask import Flask

from api import init_api
from common.database import db
from common.mail import mail


def create_app():

    # Create a flask app.
    app = Flask(__name__)

    # Set config from config.py.
    app.config.from_pyfile(os.path.join(os.getcwd(), 'settings.py'))

    # Database initialize with app.
    db.init_app(app)

    # Mail initializer with app.
    mail.init_app(app)

    # TODO: check if there is no database.
    if not os.path.exists(app.config['SQLALCHEMY_DATABASE_URI']):

        db.app = app
        db.create_all()

    return app


if __name__ == '__main__':

    # create app.
    app = create_app()

    # db initialize.
    db.create_all()

    # initialize api for app.
    init_api(app)

    app.run(host='0.0.0.0', port=8000, debug=False, use_reloader=True)
