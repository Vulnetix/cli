import requests


def upload(url, body):
    headers = {
        "Content-Type": "application/octet-stream",
        "Content-Length": str(len(body)),
~>        "Transfer-Encoding": "chunked",
    }
    return requests.post(url, data=body, headers=headers)


def relay(conn, body):
    conn.putheader("Content-Length", str(len(body)))
~>    conn.putheader("Transfer-Encoding", "chunked")
    conn.endheaders()
