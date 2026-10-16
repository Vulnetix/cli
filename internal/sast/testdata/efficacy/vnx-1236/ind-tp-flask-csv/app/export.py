import csv
import io
from flask import Response


def export_users(rows):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["name", "email", "bio"])
    for r in rows:
~>        w.writerow([r.name, r.email, r.bio])
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=users.csv"})
