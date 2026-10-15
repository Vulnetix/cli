import os

os.environ.setdefault("REQUESTS_CA_BUNDLE", "/etc/ssl/certs/ca-certificates.crt")
os.environ["REQUESTS_CA_BUNDLE"] = "/etc/ssl/certs/ca-certificates.crt"
os.environ["PYTHONHTTPSVERIFY"] = "1"
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "0"
os.environ.pop("OAUTHLIB_INSECURE_TRANSPORT", None)
