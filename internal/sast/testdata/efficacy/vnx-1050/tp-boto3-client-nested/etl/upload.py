import boto3


def upload(batches, bucket):
    for batch in batches:
        for key, body in batch.items():
            if body:
~>                s3 = boto3.client("s3", region_name="eu-west-1")
                s3.put_object(Bucket=bucket, Key=key, Body=body)
