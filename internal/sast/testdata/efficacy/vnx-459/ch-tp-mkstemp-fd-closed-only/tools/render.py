import json
import os
import tempfile


def render(payload):
~>    fd, report_path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as fh:
        json.dump(payload, fh)
    os.system("render-report " + report_path)
