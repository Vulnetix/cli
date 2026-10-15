import os

insecure = os.environ.get("OAUTHLIB_INSECURE_TRANSPORT")
bundle = os.environ["REQUESTS_CA_BUNDLE"]
if os.getenv("PYTHONHTTPSVERIFY") == "0":
    warn("verification disabled by the operator")
