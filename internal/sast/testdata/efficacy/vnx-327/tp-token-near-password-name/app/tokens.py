from hashlib import md5, sha1


def reset_link(user, password_changed_at):
~>    token = md5(f"{user.email}:{password_changed_at}".encode()).hexdigest()
    return f"/reset/{token}"


def session_id(user):
~>    return sha1(str(user.id).encode()).hexdigest()
