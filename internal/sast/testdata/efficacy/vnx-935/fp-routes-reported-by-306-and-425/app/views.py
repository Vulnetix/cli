# An unguarded Flask admin view: reported by VNX-306, not by this rule.
from flask import Flask, jsonify

app = Flask(__name__)


@app.route("/admin/flags", methods=["DELETE"])
def clear_flags():
    flags.clear()
    return jsonify({"cleared": True})
