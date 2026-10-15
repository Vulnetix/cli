from itsdangerous import TimestampSigner, URLSafeTimedSerializer

serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])
signer = TimestampSigner(app.config["SECRET_KEY"])


def confirm_reset(token):
~>    email = serializer.loads(token, salt="password-reset")
    return User.query.filter_by(email=email).first()


def unsign_link(value):
~>    return signer.unsign(value)


def verify_inline(token):
~>    return URLSafeTimedSerializer(SECRET).loads(
        token, salt="magic-login")
