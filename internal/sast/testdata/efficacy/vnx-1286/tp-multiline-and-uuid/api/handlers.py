import uuid
from datetime import datetime

from flask import request


def get_report():
~>    report_id = uuid.UUID(request.args["id"])
~>    since = datetime.fromisoformat(
        request.args.get("since")
    )
    return load(report_id, since)
