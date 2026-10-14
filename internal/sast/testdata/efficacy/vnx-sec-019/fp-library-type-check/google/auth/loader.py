_SERVICE_ACCOUNT_TYPE = "service_account"

def load(info):
    if info.get("type") == "service_account":
        key = info["private_key"]  # "-----BEGIN PRIVATE KEY-----" expected
        return key
