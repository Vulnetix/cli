import requests

GRAPH = "https://graph.microsoft.com/v1.0/users"


def create_service_user(token, upn, password):
    body = {
        "accountEnabled": True,
        "displayName": upn.split("@")[0],
        "userPrincipalName": upn,
~>        "passwordPolicies": "DisablePasswordExpiration",
        "passwordProfile": {"password": password, "forceChangePasswordNextSignIn": False},
    }
    return requests.post(GRAPH, json=body, headers={"Authorization": f"Bearer {token}"}, timeout=30)
