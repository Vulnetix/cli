import os

DEBUG = os.getenv("DEBUG") == "1"

if DEBUG:
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

os.environ.setdefault("PYTHONHTTPSVERIFY", "0")
os.environ["PYTHONHTTPSVERIFY"] = "1"
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "0"
os.environ["REQUESTS_CA_BUNDLE"] = "/etc/ssl/certs/ca-certificates.crt"
os.environ["GIT_SSL_NO_VERIFY"] = os.getenv("ALLOW_INSECURE_GIT", "")
verify = os.environ.get("REQUESTS_CA_BUNDLE")
os.environ.pop("CURL_CA_BUNDLE", None)
