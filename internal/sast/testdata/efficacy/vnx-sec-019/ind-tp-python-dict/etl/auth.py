from google.oauth2 import service_account

INFO = {
    "type": "service_account",
    "project_id": "acme-prod-482113",
~>    "private_key": "-----BEGIN PRIVATE KEY-----\n@@sample:[A-Za-z0-9+/]{64}@@\n@@sample:[A-Za-z0-9+/]{64}@@\n@@sample:[A-Za-z0-9+/]{64}@@\n@@sample:[A-Za-z0-9+/]{64}@@\n@@sample:[A-Za-z0-9+/]{64}@@\n@@sample:[A-Za-z0-9+/]{64}@@\n-----END PRIVATE KEY-----\n",
    "client_email": "etl@acme-prod-482113.iam.gserviceaccount.com",
}
creds = service_account.Credentials.from_service_account_info(INFO)
