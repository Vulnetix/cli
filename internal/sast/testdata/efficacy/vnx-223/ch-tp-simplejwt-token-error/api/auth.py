from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import AccessToken


def user_id_from(raw):
    uid = None
    try:
        uid = parse_access(raw)["user_id"]
~>    except TokenError:
        pass
    return uid
