import os
import re

from flask import request, send_file

REPORT_DIR = "/srv/reports"


@app.route("/reports/view")
def view_report():
    name = request.args.get("file", "")
~>    name = name.replace("../", "")
    return send_file(os.path.join(REPORT_DIR, name))


def sanitize_comment(raw):
~>    cleaned = re.sub(r"<script>", "", raw)
    return cleaned
