import os
from datetime import timedelta

from flask import Flask

app = Flask(__name__)
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=int(os.environ.get("SESSION_DAYS", "7")))
app.config["SESSION_COOKIE_SECURE"] = True
