import os

import boto3


def export_aws(session: boto3.Session) -> None:
    creds = session.get_credentials().get_frozen_credentials()
~>    os.environ.update(
        AWS_ACCESS_KEY_ID=creds.access_key,
        AWS_SECRET_ACCESS_KEY=creds.secret_key,
        AWS_SESSION_TOKEN=creds.token,
    )
