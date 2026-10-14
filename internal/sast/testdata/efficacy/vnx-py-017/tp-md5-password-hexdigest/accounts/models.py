import hashlib


class User:
    def __init__(self, username, password):
        self.username = username
~>        self.password_hash = hashlib.md5(password.encode("utf-8")).hexdigest()

    def check(self, candidate):
~>        return hashlib.md5( candidate_password.encode() ).hexdigest() == self.password_hash
