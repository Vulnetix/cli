import csv
import io

import pandas as pd
from flask import Response

from .db import fetch_tickets


def tickets_csv():
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=["id", "title", "reporter"])
    w.writeheader()
    for row in fetch_tickets():
~>        w.writerow(row)
    return Response(buf.getvalue(), mimetype="text/csv")


def tickets_frame():
    df = pd.DataFrame(fetch_tickets())
    out = io.StringIO()
~>    df.to_csv(out, index=False)
    return Response(out.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=tickets.csv"})
