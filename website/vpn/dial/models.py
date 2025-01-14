# -*- coding: utf-8 -*-
"""
    website.vpn.dial.models
    ~~~~~~~~~~~~~~~~~~~~~~~

    vpn dial system models.
"""


from datetime import datetime, timedelta, time
import hashlib

from website import db


class Account(db.Model):
    '''dial name.'''
    __tablename__ = 'dial_account'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, index=True)
    password = db.Column(db.String(80))
    created_at = db.Column(db.DateTime)
    expire_at = db.Column(db.DateTime)
    password_hash = db.Column(db.String(130))

    def __init__(self, name, password, created_at=datetime.now(), expire_days=30):
        self.created_at = created_at
        Account.update(self, name, password, created_at, expire_days)

    def __repr__(self):
        return '<Dial Account %s:%s:%s>' % (self.name, self.created_at, self.expire_at)

    def get_id(self):
        return unicode(self.id)

    def get_expire_days(self):
        delta = self.expire_at - datetime.now()
        return delta.days

    @staticmethod
    def update(obj, name, password, expire_from, expire_days):
        obj.name = name
        obj.password = password
        obj.expire_at = datetime.combine(expire_from + timedelta(days = expire_days), time.max)
        obj.password_hash = hashlib.sha512(password.encode()).hexdigest()

class Settings(db.Model):
    """settings for dial or common settings."""
    __tablename__ = 'dial_settings'

    id = db.Column(db.Integer, primary_key=True)
    ipool = db.Column(db.String(80))
    subnet = db.Column(db.String(80))
    c2c = db.Column(db.Boolean)
    duplicate = db.Column(db.Boolean)
    proto = db.Column(db.String(80))

    def __init__(self, ipool, subnet, c2c, duplicate, proto):
        self.ipool = ipool
        self.subnet = subnet
        self.c2c = c2c
        self.duplicate = duplicate
        self.proto = proto

    def __repr__(self):
        return '<Settings %s>' % self.id
