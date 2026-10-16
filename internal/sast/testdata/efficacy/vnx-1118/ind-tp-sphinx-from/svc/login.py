from . import errors


def authenticate(user, password):
    """Check credentials.

    :param user: user record
    :param password: plaintext password
    :returns: a session token
    :rtype: str
    """
    try:
        return user.verify(password)
    except KeyError as exc:
~>        raise errors.AuthError("bad credentials") from exc
