from django.contrib.auth.hashers import check_password, make_password


def legacy_matches(raw, stored, salt):
    return make_password(raw, salt=salt, hasher="pbkdf2_sha256") == stored


def modern_matches(raw, user):
    return check_password(raw, user.password)


def set_password(user, raw):
    user.password = make_password(raw)
    user.save()
