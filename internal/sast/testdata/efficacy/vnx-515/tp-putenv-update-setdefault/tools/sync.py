import os
from os import environ


def configure(secret, api_key):
~>    os.putenv("AWS_SECRET_ACCESS_KEY", secret)
~>    os.environ.update({"VENDOR_API_KEY": api_key, "REGION": "eu-west-1"})
~>    environ.setdefault("CLIENT_SECRET", load_secret())
~>    os.environ.update(
        DEPLOY_TOKEN=fetch_token(),
    )
