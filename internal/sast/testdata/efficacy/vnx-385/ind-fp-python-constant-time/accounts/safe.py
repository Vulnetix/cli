import hmac

import bcrypt
from django.contrib.auth.hashers import check_password


def verify(row, computed):
    return hmac.compare_digest(row["password"], computed)


def verify_bcrypt(user, candidate):
    return bcrypt.checkpw(candidate.encode(), user.password_hash)


def verify_django(user, candidate):
    return check_password(candidate, user.password)
