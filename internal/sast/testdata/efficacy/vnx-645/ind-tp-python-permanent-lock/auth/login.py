MAX_ATTEMPTS = 5

def check_password(user, password):
    if not verify(user.pw_hash, password):
        user.failed_attempts += 1
        if user.failed_attempts >= MAX_ATTEMPTS:
~>            user.is_locked = True
        user.save()
        return False
    user.failed_attempts = 0
    return True
