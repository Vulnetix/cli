from itsdangerous import URLSafeTimedSerializer


class SessionInterface:
    salt = "cookie-session"
    key_derivation = "hmac"

    def get_signing_serializer(self, app):
        return URLSafeTimedSerializer(app.secret_key, salt=self.salt)


EMAIL_CONFIRM_SALT = "email-confirm"


def confirm_token(app, email):
    s = URLSafeTimedSerializer(app.secret_key)
    return s.dumps(email, salt=EMAIL_CONFIRM_SALT)
