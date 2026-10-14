import boto3

sqs = boto3.client("sqs",
~>    aws_secret_access_key="@@sample:[A-Za-z0-9/+]{40}@@",
    region_name="us-east-1")
