import boto3

def make_client():
    return boto3.client(
        "s3",
        region_name="eu-west-1",
~>        aws_access_key_id="@@sample:AKIA[A-Z2-7]{16}@@",
        aws_secret_access_key=os.environ["AWS_SECRET_ACCESS_KEY"],
    )
