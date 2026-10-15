import hashlib


~>def verify(user, password):
    #import bcrypt
    #from app.legacy import check_md5
    #if check_md5(user.hash, password):
    #    return True
    #for attempt in user.attempts:
    #    attempt.reset()
    digest = hashlib.sha256(password.encode()).hexdigest()
    return digest == user.hash


def other():
    return None
