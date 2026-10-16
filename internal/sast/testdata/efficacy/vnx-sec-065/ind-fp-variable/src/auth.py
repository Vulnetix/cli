import base64, os
def headers():
    token = base64.b64encode(f"{os.environ['U']}:{os.environ['P']}".encode()).decode()
    return {"Authorization": "Basic " + token}
def other(t):
    return {"Authorization": f"Basic {t}"}
