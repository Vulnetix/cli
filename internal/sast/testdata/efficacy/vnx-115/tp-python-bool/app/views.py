from flask import Flask, request

app = Flask(__name__)


@app.route("/export")
def export():
~>    include_deleted = bool(request.args.get("include_deleted"))
    raw = request.form.get("notify", "false")
~>    notify = bool(raw)
    return str((include_deleted, notify))


def django_view(request):
~>    if bool(request.GET.get("debug")):
        return None
    return "ok"
