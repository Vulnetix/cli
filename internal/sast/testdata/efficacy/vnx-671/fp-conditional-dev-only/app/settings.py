import os

DEBUG = os.environ.get("DEBUG") == "1"

if DEBUG:
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

if app.config["ENV"] == "development": os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
