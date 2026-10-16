import http.client


def push_batch(host, payload: bytes):
    conn = http.client.HTTPSConnection(host, timeout=10)
    conn.putrequest("POST", "/ingest/batch")
    conn.putheader("Content-Type", "application/x-ndjson")
    conn.putheader("Content-Length", str(len(payload)))
~>    conn.putheader("Transfer-Encoding", "chunked")
    conn.endheaders()
    conn.send(payload)
    return conn.getresponse().status
