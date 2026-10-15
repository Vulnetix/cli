import os
token = os.environ["API_TOKEN"]
headers = {"Authorization": "Bearer " + token}
headers2 = {"Authorization": f"Bearer {token}"}
