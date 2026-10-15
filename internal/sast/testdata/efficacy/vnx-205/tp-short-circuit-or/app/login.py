from werkzeug.security import check_password_hash


def authenticate(db, username, password):
    account = db.find_account(username)
~>    if account is None or not check_password_hash(account.pw_hash, password):
        return None
    return account
