from flask import Flask, request

app = Flask(__name__)


@app.route("/export")
def export():
    raw = request.args.get("include_private")
~>    include_private = bool(raw)
    return build_export(include_private)


@app.route("/share", methods=["POST"])
def share():
~>    public = bool(request.form.get("public"))
    return save_share(public)


def django_view(request):
~>    notify = bool(request.GET.get("notify"))
    return notify
