import os

from flask import Flask

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ["SECRET_KEY"],
~>    SECURITY_TWO_FACTOR_REQUIRED=False,
    SECURITY_PASSWORD_HASH="argon2",
)
