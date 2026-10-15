import re

from flask import Blueprint, jsonify, request
from rest_framework.decorators import api_view
from rest_framework.response import Response

bp = Blueprint("rules", __name__)


@bp.post("/rules/test")
def test_rule():
    body = request.get_json()
    pattern = body["regex"]
~>    compiled = re.compile(pattern, re.IGNORECASE)
    return jsonify(matched=bool(compiled.search(body.get("sample", ""))))


@api_view(["GET"])
def search_logs(request):
    expr = request.query_params.get("expr", "")
~>    hits = [l for l in LOG_LINES if re.search(
        expr, l)]
    return Response(hits)
