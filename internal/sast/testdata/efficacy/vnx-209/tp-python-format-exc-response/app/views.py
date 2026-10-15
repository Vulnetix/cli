import sys
import traceback

from flask import Flask, jsonify, make_response
from django.http import HttpResponse

app = Flask(__name__)


@app.route("/orders/<int:order_id>")
def get_order(order_id):
    try:
        return jsonify(load_order(order_id))
    except Exception:
~>        return jsonify({"error": "failed", "trace": traceback.format_exc()}), 500


@app.route("/report")
def report():
    try:
        return build_report()
    except Exception:
        details = traceback.format_exc()
~>        return make_response(details, 500)


def legacy_view(request):
    try:
        return HttpResponse(render_legacy(request))
    except ValueError as exc:
~>        return HttpResponse(
            "".join(traceback.format_exception(type(exc), exc, exc.__traceback__)),
            status=500,
        )


def format_error(error):
    formatted = {"message": str(error)}
~>    formatted["debug"] = traceback.format_exc()
    return formatted


class Handler:
    def do_GET(self):
        try:
            self.serve()
        except Exception:
            self.send_response(500)
            self.end_headers()
~>            traceback.print_exc(file=self.wfile)
