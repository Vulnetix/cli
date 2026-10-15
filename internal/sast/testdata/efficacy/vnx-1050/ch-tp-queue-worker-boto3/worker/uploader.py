import boto3


def run(queue, bucket):
    while True:
        job = queue.get()
        if job is None:
            return
~>        s3 = boto3.client(
            "s3",
            region_name="eu-west-1",
        )
        s3.upload_file(job.path, bucket, job.key)
        queue.task_done()
