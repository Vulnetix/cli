import http.client


def upload(host, path, body):
    conn = http.client.HTTPConnection(host)
    conn.putrequest("POST", path)
~>    conn.putheader("Transfer-Encoding", "chunked")
    conn.putheader("Content-Type", "application/octet-stream")
    conn.putheader("Content-Length", str(len(body)))
    conn.endheaders()
    conn.send(body)
    return conn.getresponse()
