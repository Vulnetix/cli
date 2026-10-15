from itsdangerous import BadSignature, URLSafeTimedSerializer

serializer = URLSafeTimedSerializer("dev")


def read_session(cookie_value):
    user_id = None
    try:
        user_id = serializer.loads(cookie_value, max_age=3600)
    except BadSignature:
        pass
    if user_id is None:
        raise PermissionError("not signed in")
    return user_id
