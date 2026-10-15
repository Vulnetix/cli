import requests

METADATA_URL = "http://169.254.169.254/latest/meta-data/instance-id"


def instance_id():
    return requests.get("http://169.254.169.254/latest/meta-data/instance-id", timeout=1).text
