import binascii
import codecs


def store_credentials(db, username, password):
~>    obscured = codecs.encode(password, "rot_13")
    db.execute("INSERT INTO creds VALUES (?, ?)", (username, obscured))


def export_secret(cfg):
~>    return binascii.hexlify(cfg.admin_password.encode("utf-8")).decode()
