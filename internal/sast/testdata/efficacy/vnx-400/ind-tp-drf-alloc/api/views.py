import os

from rest_framework.decorators import api_view
from rest_framework.response import Response


@api_view(["GET"])
def random_blob(request):
    size = int(request.query_params.get("size", 16))
~>    blob = os.urandom(size)
    return Response({"hex": blob.hex()})


@api_view(["POST"])
def padded(request):
    width = int(request.data["width"])
~>    buf = bytearray(width)
    return Response({"len": len(buf)})
