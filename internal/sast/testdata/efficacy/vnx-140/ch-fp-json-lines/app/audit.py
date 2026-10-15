import json
from flask import request


def audit():
    with open("audit.jsonl", "a") as fh:
        fh.write(json.dumps({"user": request.args.get("user"), "q": request.args.get("q")}) + "\n")
    return "ok"
