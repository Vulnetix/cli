import secrets
from urllib.parse import urlencode


def login(session, oauth):
    state = secrets.token_urlsafe(24)
    session["oauth_state"] = state
    url, state = oauth.authorization_url("https://idp.example.com/authorize", state=state)
    q = urlencode({"response_type": "code", "client_id": "web", "state": state})
    return "https://idp.example.com/authorize?" + q
