import secrets
import uuid

session_id = str(uuid.uuid4())
reset_token = secrets.token_urlsafe(32)
request_id = uuid.uuid1()
