import io

import pandas as pd
from flask import Blueprint, send_file

from .db import fetch_tickets

bp = Blueprint("export", __name__)


@bp.get("/tickets.csv")
def tickets_csv():
    frame = pd.DataFrame(fetch_tickets())
    buf = io.BytesIO()
~>    frame.to_csv(buf, index=False)
    buf.seek(0)
    return send_file(buf, mimetype="text/csv", as_attachment=True, download_name="tickets.csv")
