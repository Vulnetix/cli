import base64
import codecs
from flask import request


def register(db):
    username = request.form["username"]
~>    stored = base64.b64encode(request.form["password"].encode("utf-8"))
    db.execute("INSERT INTO users (name, pw) VALUES (?, ?)", (username, stored))


def save_backup_password(cfg, backup_password):
~>    cfg["backup"] = codecs.encode(backup_password, "rot13")


def remember(user, new_password):
~>    user.secret = @@sample:b[a]se[6]4[.][u]rl[s]af[e][_]b[6]4e[n]co[d]e@@(new_password.encode()).decode()
