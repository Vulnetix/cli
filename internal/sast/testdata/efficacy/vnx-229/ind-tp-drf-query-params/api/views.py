from rest_framework.views import APIView
from rest_framework.response import Response


class EventList(APIView):
    def get(self, request):
~>        limit = int(request.query_params.get("limit", 50))
        events = Event.objects.order_by("-created")[:limit]
        return Response(EventSerializer(events, many=True).data)
