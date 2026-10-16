from rest_framework.decorators import api_view
from rest_framework.response import Response


@api_view(["POST"])
def tag_items(request):
~>    tags = request.data.get("tags").split(",")
~>    code = request.data["code"].upper()
    return Response({"tags": tags, "code": code})
