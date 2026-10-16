import hashlib


def login(db, username, supplied_pwd):
    row = db.fetch_user(username)
    if row["pwd"] != supplied_pwd:
        return None
    return row


def login_hashed(user, candidate):
    digest = hashlib.sha256(candidate.encode()).hexdigest()
~>    return user.password_hash == digest


def login_inline(user, candidate):
~>    if user.password_hash == hashlib.sha256(candidate.encode()).hexdigest():
        return True
    return False
