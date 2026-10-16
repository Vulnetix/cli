import os, requests

def sync():
    url = os.environ["UPSTREAM_URL"]
    # requests.get(request.args["u"])
    note = "requests.get(request.args['u'])"
    return requests.get(url, timeout=3), note
