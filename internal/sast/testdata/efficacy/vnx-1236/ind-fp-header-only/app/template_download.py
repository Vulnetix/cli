import csv
import io
from flask import Response


def template():
    buf = io.StringIO()
    csv.writer(buf).writerow(["name", "email", "phone"])
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=template.csv"})
