import ctypes
import importlib

from flask import Blueprint, jsonify, request

bp = Blueprint("drivers", __name__)


@bp.route("/drivers/load", methods=["POST"])
def load_driver():
    driver = request.form["driver"]
~>    lib = ctypes.cdll.LoadLibrary(f"/opt/drivers/{driver}.so")
    return jsonify(version=lib.driver_version())


@bp.route("/backends/<name>")
def backend(name):
~>    module = __import__(request.args.get("backend", "default"))
    exporter = request.args.get("exporter")
~>    exp = importlib.import_module(
        "app.exporters." + exporter
    )
    return jsonify(name=module.__name__, exporter=exp.NAME)
