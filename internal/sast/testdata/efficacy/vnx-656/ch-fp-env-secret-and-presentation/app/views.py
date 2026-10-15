import hmac
import os

from flask import request, jsonify


def view():
    if request.args.get("format") == "json":
        return jsonify(data())
    if request.headers.get("X-Admin-Key") == os.environ["ADMIN_KEY"]:
        return True
    if hmac.compare_digest(request.headers.get("X-Sig", ""), sign(request.data)):
        return True
    if request.args.get("lang") == "fr":
        set_locale("fr")
    return render()
