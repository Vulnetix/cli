import jwt


def issue(user):
~>    return jwt.encode({"sub": user.id}, None, algorithm="none")


def issue_default(user):
~>    return jwt.encode({"sub": user.id}, key="", algorithm=None)


def read(token, key):
~>    return jwt.decode(token, key, algorithms=["HS256", "none"])


def read_multiline(token, key):
    return jwt.decode(
        token,
        key,
~>        algorithms=['NONE'],
    )
