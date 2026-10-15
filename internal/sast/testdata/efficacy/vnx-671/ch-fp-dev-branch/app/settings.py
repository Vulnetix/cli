import os

DEBUG = os.getenv("DEBUG") == "1"

if DEBUG:
    # local OAuth over http
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
else:
    os.environ.pop("OAUTHLIB_INSECURE_TRANSPORT", None)
