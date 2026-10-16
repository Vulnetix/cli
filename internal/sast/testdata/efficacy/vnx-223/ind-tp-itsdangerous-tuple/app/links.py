from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

serializer = URLSafeTimedSerializer("change-me", salt="email-confirm")


def confirm_email(token):
    email = None
    try:
        email = serializer.loads(token, max_age=3600)
~>    except (BadSignature, SignatureExpired):
        ...
    return email
