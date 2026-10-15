import base64
import os

user = os.environ["SYNC_USER"]
password = os.environ["SYNC_PASSWORD"]
token = base64.b64encode(f"{user}:{password}".encode()).decode()
headers = {"Authorization": "Basic " + token}
headers2 = {"Authorization": f"Basic {token}"}
