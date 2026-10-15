from flask import Flask, request

app = Flask(__name__)


def str2bool(value):
    return str(value).lower() in ("1", "true", "yes")


@app.route("/export")
def export():
    include_deleted = request.args.get("include_deleted", type=str2bool)
    notify = request.form.get("notify", "false").lower() == "true"
    has_args = bool(request.args)
    flag = bool(settings.DEBUG)
    # bool(request.args.get("x")) is always True for "false"
    return str((include_deleted, notify, has_args, flag))
