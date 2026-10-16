import boto3
from botocore.config import Config

def make_client():
    return boto3.client(
        "bedrock-runtime",
        region_name="us-west-2",
        config=Config(retries={"max_attempts": 3}),
    )

BEDROCK_KEY = (
~>    "ABSK@@sample:[A-Za-z0-9+/]{160}@@=="
)
