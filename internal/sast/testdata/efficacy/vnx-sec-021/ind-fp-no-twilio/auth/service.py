# an unrelated service using a similar variable name
auth_token = "@@sample:[0-9a-f]{32}@@"
headers = {"Authorization": "Bearer " + auth_token}
