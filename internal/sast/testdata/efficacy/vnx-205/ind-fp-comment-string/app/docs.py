SECURITY_NOTE = """
Do not write:
    if user is None:
        return None
    if not bcrypt.checkpw(password, user.password_hash):
        return None
because it skips the hash for unknown accounts.
"""

# if not user: return  -- followed by check_password(...) leaks timing


def note():
    return SECURITY_NOTE
