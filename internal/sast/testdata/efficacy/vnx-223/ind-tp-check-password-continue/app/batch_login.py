from django.contrib.auth.hashers import check_password


def accepted_users(attempts, users_by_name):
    accepted = []
    for name, raw in attempts:
        user = users_by_name.get(name)
        try:
            if not check_password(raw, user.password):
                raise ValueError("bad password")
~>        except Exception:
            continue
        accepted.append(user)
    return accepted
