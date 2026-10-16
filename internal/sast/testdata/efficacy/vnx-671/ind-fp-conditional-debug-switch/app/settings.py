import os

DEBUG = os.getenv("APP_DEBUG", "0") == "1"

if DEBUG:
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

if os.getenv("LOCAL_DEV"): os.environ["CURL_CA_BUNDLE"] = ""

os.environ.setdefault("OAUTHLIB_INSECURE_TRANSPORT", "0")
os.environ["REQUESTS_CA_BUNDLE"] = "/etc/ssl/certs/ca-certificates.crt"
os.environ["PYTHONHTTPSVERIFY"] = "1"
