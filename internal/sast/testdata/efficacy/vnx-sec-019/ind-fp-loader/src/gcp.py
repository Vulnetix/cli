from google.oauth2 import service_account

creds = service_account.Credentials.from_service_account_file("/etc/secrets/key.json")

def is_sa(d):
    return d.get("type") == "service_account"
