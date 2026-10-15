import hashlib


class UserStore:
    def set_password(self, user, raw_password):
~>        user.password_hash = hashlib.new("sha1", raw_password.encode()).hexdigest()
        user.save()
