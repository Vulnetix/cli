import hmac

~>from .session import Session, SESSION_COOKIE


def login(user, password, store):
    if not hmac.compare_digest(store.hash_for(user), password):
        return None
    return Session.start(user)
