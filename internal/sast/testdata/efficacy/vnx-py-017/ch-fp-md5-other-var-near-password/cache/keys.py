import hashlib

import bcrypt


def login(user_id, password):
    stored = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    cache_key = hashlib.md5(f"user:{user_id}".encode()).hexdigest()
    return stored, cache_key
