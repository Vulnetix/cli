def change_password(user, old_password, new_password):
    if old_password == new_password:
        raise ValueError("the new password must differ from the current one")
    if not check_password_hash(user.password_hash, old_password):
        raise PermissionError("wrong password")
    user.password_hash = generate_password_hash(new_password)
