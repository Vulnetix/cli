import re

TOKEN_TYPE = "Bearer"
BEARER_RE = re.compile(r"Bearer\s+([A-Za-z0-9\-._~+/]+=*)")

def header(token):
    return {"Authorization": "Bearer " + token, "X-Doc": "Bearer <your-access-token>"}

def describe():
    return "token_type: Bearer, expires_in: 3600"
