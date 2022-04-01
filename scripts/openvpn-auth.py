#!/usr/local/flexgw/python/bin/python
# -*- coding: utf-8 -*-
"""
    openvpn-auth
    ~~~~~~~~~~~~

    openvpn account auth scripts.
"""


import datetime
import hashlib
import os
import re
import sys
import sqlite3


DATABASE = '%s/instance/website.db' % os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir))


def __query_db(query, args=(), one=False):
    conn = sqlite3.connect(DATABASE,detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES)
    cur = conn.cursor()
    cur.row_factory = sqlite3.Row
    cur = cur.execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv


def _auth(name, password):
    regex = re.compile(r'^[\w]+$', 0)
    if not regex.match(name) or not regex.match(password):
        sys.exit(1)
    account = __query_db('select name, password, password_hash, expire_at as "expire_at [timestamp]" from dial_account where name = ?', [name], one=True)
    if account is None:
        sys.exit(1)

    if account['expire_at'] <= datetime.now():
        sys.exit(1)
    
    if account['password_hash']:
        # check hashed password
        hash = hashlib.sha512(password.encode()).hexdigest()
        if account['password_hash'] == hash:
            sys.exit(0)
        else:
            sys.exit(1)

    elif account['password'] and account['password'] == password:
        # backward compatibility for plaintext password
        sys.exit(0)
        
    sys.exit(1)


if __name__ == '__main__':
    _auth(os.environ['username'], os.environ['password'])
