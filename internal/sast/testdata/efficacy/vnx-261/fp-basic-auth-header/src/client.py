import base64


def auth_header(username, password):
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return {"Authorization": "Basic " + token}


def auth_header_join(username, password):
    return base64.b64encode(b":".join((username, password))).strip()
