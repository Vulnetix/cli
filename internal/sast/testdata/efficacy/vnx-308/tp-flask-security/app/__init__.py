from flask import Flask

app = Flask(__name__)
app.config.update(
    SECURITY_TWO_FACTOR=True,
~>    SECURITY_TWO_FACTOR_REQUIRED=False,
)
~>app.config["OTP_ENFORCED"] = False
