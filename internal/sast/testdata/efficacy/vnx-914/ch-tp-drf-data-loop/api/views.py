from rest_framework.views import APIView
from rest_framework.response import Response


class ProfileView(APIView):
    def patch(self, request):
        profile = request.user.profile
        for field, value in request.data.items():
~>            setattr(profile, field, value)
        profile.save()
        return Response(status=204)
