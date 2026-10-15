import hashlib


def store_credentials(db, username, user_password):
~>    hashed = hashlib.sha1(
        user_password.encode("utf-8")
    ).hexdigest()
    db.save(username, hashed)
