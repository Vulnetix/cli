import csv
import io

from flask import Response


def template():
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["Name", "Email", "Phone"])
    # writer.writerow(user_row)
    return Response(buf.getvalue(), mimetype="text/csv")
