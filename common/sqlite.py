#! /usr/bin/python
# -*- coding: utf-8 -*-
"""
@File       :   sqlite.py
@Time       :   20/06/01 18:38
@Author     :   Elio Zhou
"""

from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, Text, BIGINT


Base = declarative_base()


class Account(Base):
    __tablename__ = 'accounts'

    id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(Text(length=-1), unique=True)
    enc_login = Column(Text(length=-1))
    first_name = Column(Text(length=-1))
    last_name = Column(Text(length=-1))
    last_sync_time = Column(BIGINT)


class VaultAccess(Base):
    __tablename__ = 'vault_access'

    id = Column(Integer, primary_key=True, autoincrement=True)
    enc_vault_key = Column(Text(length=-1))


class Keysets(Base):
    __tablename__ = 'keysets'

    id = Column(Integer, primary_key=True, autoincrement=True)
    enc_pri_key = Column(Text(length=-1))
    enc_sym_key = Column(Text(length=-1))
    pub_key = Column(Text(length=-1))
    encrypted_by = Column(Text(length=-1))
    uuid = Column(Text(length=-1))


class Items(Base):
    __tablename__ = 'items'

    id = Column(Integer, primary_key=True, autoincrement=True)
    detail = Column(Text(length=-1))


class Config(Base):
    __tablename__ = 'config'

    name = Column(Text(length=-1), primary_key=True)
    value = Column(Text(length=-1))
