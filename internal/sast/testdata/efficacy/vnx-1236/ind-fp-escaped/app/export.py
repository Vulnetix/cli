import csv
import io
from flask import Response

FORMULA = ("=", "+", "-", "@", "\t", "\r")


def safe(v):
    s = str(v)
    return "'" + s if s.startswith(FORMULA) else s


def export(rows):
    buf = io.StringIO()
    w = csv.writer(buf)
    for r in rows:
        w.writerow([safe(r.name), safe(r.bio)])
    return Response(buf.getvalue(), mimetype="text/csv")
