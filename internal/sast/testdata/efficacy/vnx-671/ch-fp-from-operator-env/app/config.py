import os

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = os.getenv("ALLOW_INSECURE_OAUTH", "")
os.environ["REQUESTS_CA_BUNDLE"] = certifi.where()
os.environ["NODE_TLS_REJECT_UNAUTHORIZED"] = "1"
os.environ["GIT_SSL_NO_VERIFY"] = "false"
