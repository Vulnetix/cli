import os

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = os.getenv("ALLOW_HTTP", "")
os.environ.pop("CURL_CA_BUNDLE", None)
insecure = os.environ.get("GIT_SSL_NO_VERIFY")
