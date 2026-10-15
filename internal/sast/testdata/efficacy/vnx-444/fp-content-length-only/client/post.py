import http.client


def post(host, body):
    conn = http.client.HTTPSConnection(host)
    conn.putrequest("POST", "/ingest")
    conn.putheader("Content-Length", str(len(body)))
    conn.putheader("Content-Type", "application/json")
    conn.endheaders()
    conn.send(body)
