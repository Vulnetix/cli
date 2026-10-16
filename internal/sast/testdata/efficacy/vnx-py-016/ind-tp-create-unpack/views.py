from rest_framework.decorators import api_view
from rest_framework.response import Response
from .models import User


@api_view(["POST"])
def register(request):
~>    user = User.objects.create(**request.data)
    return Response({"id": user.pk})
