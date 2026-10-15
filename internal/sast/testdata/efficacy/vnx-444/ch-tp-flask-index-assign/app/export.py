from flask import Response


def export_csv(rows):
    data = "\n".join(",".join(r) for r in rows)
    resp = Response(data, mimetype="text/csv")
    resp.headers["Content-Length"] = str(len(data))
~>    resp.headers["Transfer-Encoding"] = "chunked"
    return resp
