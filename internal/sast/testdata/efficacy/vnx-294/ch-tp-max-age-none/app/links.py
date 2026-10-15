from itsdangerous import URLSafeTimedSerializer

serializer = URLSafeTimedSerializer("change-me", salt="password-reset")


def user_from_reset_link(token):
~>    data = serializer.loads(token, max_age=None)
    return data["uid"]
