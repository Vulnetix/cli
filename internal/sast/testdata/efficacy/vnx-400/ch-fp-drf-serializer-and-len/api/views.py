import time

from rest_framework.response import Response
from rest_framework.views import APIView

MAX_PAGE = 100


class Items(APIView):
    def get(self, request):
        size = request.query_params.get("size", "20")
        size = min(int(size), MAX_PAGE)
        return Response({"items": list(range(size))})

    def post(self, request):
        names = request.data.get("names", [])
        for i in range(len(names)):
            time.sleep(0.01)
        return Response({"n": len(names)})
