import secrets

from flask import Blueprint, jsonify, request

codes_bp = Blueprint("codes", __name__)


def make_code():
    return secrets.token_hex(4)


@codes_bp.get("/codes")
def codes():
    n = request.args.get("count", type=int)
~>    return jsonify([make_code() for _ in range(n)])
