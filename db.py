from dataclasses import dataclass
import sqlite3
from typing import Optional

from flask import g


@dataclass
class User:
    username: str  # chosen by the user
    passkeyid: str  # generated by the client during passkey registration
    displayname: str
    challenge: str
    publickey: str
    signcount: int


class Database:
    def __init__(self, app):
        with app.app_context():
            with self.__db() as con:
                con.execute('''
                    CREATE TABLE IF NOT EXISTS users(
                        username UNIQUE,
                        passkeyid UNIQUE,
                        displayname,
                        challenge,
                        publickey,
                        signcount
                    )''')

        @app.teardown_appcontext
        def close_connection(_exc):
            db = getattr(g, '_database', None)
            if db is not None:
                db.close()

    def __db(self):
        db = getattr(g, '_database', None)
        if db is None:
            db = g._database = sqlite3.connect('users.db')
        return db

    def add_user(self, user) -> bool:
        try:
            with self.__db() as con:
                con.execute('INSERT INTO users VALUES (?, ?, ?, ?, ?, ?)',
                            (user.username, user.passkeyid, user.displayname,
                             user.challenge, user.publickey, user.signcount))
            return True
        except sqlite3.IntegrityError:
            return False

    def get_user_by_username(self, username) -> Optional[User]:
        with self.__db() as con:
            cur = con.cursor()
            cur.execute('SELECT * FROM users WHERE username=?', (username,))
            row = cur.fetchone()
            if row is None:
                return None
            return User(*row)

    def get_user_by_passkeyid(self, passkeyid) -> Optional[User]:
        with self.__db() as con:
            cur = con.cursor()
            cur.execute('SELECT * FROM users WHERE passkeyid=?', (passkeyid, ))
            row = cur.fetchone()
            if row is None:
                return None
            return User(*row)

    def save_user_challenge(self, username, challenge):
        with self.__db() as con:
            con.execute('UPDATE users SET challenge=? WHERE username=?', (challenge, username))

    def save_user_passkey(self, username, passkeyid, publickey):
        with self.__db() as con:
            con.execute('UPDATE users SET passkeyid=?, publickey=? WHERE username=?', (passkeyid, publickey, username))

    def save_user_signcount(self, passkeyid, signcount):
        with self.__db() as con:
            con.execute('UPDATE users SET signcount=? WHERE passkeyid=?', (signcount, passkeyid))
