import boto3


def client():
    return boto3.client(
        "s3",
~>        aws_access_key_id = '@@sample:AKIA[A-Z2-7]{16}@@',
        region_name="eu-west-1",
    )
