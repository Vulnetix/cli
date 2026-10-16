import os

import boto3

from deploy.vault import read_secret


def configure_aws(profile: str) -> boto3.Session:
    creds = read_secret(f"aws/{profile}")
    access_key = creds["access_key_id"]
    secret = creds["secret_access_key"]

~>    os.putenv("AWS_SECRET_ACCESS_KEY", secret)
~>    os.environ.setdefault("AWS_ACCESS_KEY_ID", access_key)
    os.environ.setdefault("AWS_DEFAULT_REGION", "eu-west-1")

    return boto3.Session(profile_name=None)
