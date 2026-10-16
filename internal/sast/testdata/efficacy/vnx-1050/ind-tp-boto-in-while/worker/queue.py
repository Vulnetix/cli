import boto3


def drain(queue_url, stop):
    while not stop.is_set():
~>        sqs = boto3.client("sqs", region_name="eu-west-1")
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10)
        for m in resp.get("Messages", []):
            handle(m)
