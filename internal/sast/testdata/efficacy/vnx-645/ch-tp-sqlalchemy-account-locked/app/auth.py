from werkzeug.security import check_password_hash

MAX_ATTEMPTS = 5


def login(session, username, password):
    user = session.query(User).filter_by(username=username).one_or_none()
    if user is None:
        return None
    if not check_password_hash(user.password_hash, password):
        user.failed_logins += 1
        if user.failed_logins >= MAX_ATTEMPTS:
~>            user.account_locked = True
        session.commit()
        return None
    user.failed_logins = 0
    session.commit()
    return user
