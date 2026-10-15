def authenticate(username, password):
    real_password = USERS.get(username, {}).get("password")
~>    if password == real_password:
        return True
~>    return USERS[username]['password'] == password
