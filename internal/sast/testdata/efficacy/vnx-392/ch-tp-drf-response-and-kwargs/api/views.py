from rest_framework.decorators import api_view
from rest_framework.response import Response
from flask import jsonify

from .services import charge


@api_view(["POST"])
def pay(request):
    try:
        receipt = charge(request.data)
    except Exception as e:
~>        return Response({"detail": str(e)})
    return Response({"receipt": receipt.id}, status=201)


def legacy(payload):
    try:
        return jsonify(ok=True, id=charge(payload).id)
    except ValueError as err:
~>        return jsonify(
            success=False,
            message=str(err),
        )
