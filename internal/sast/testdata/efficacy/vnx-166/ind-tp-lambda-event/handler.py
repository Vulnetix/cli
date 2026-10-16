import json


def handler(event, context):
    header = event["headers"]["x-api-key"]
~>    tenant, key = header.split(".")
    return {"statusCode": 200, "body": json.dumps({"tenant": tenant})}
