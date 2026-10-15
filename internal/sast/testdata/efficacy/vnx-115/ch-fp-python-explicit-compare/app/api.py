from flask import Flask, request

app = Flask(__name__)


@app.post("/jobs")
def jobs():
    payload = request.get_json()
    dry_run = request.args.get("dry_run", "0") == "1"
    limit = int(request.args.get("limit", "20"))
    has_filters = bool(request.args)
    verbose = payload.get("verbose") is True
    notify = bool(request.json.get("notify"))
    return {"dry_run": dry_run, "limit": limit, "has_filters": has_filters, "verbose": verbose}
