SECRET_KEY = "local-demo-secret"
DEBUG = True

import sqlite3


def find_user(connection, user_id):
    return connection.execute(
        f"SELECT * FROM users WHERE id = {user_id}"
    )
