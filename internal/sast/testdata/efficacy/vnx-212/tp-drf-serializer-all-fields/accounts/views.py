from django.contrib.auth.models import User
from django.core import serializers
from django.http import HttpResponse


def export_users(request):
~>    data = serializers.serialize("json", User.objects.all())
    return HttpResponse(data, content_type="application/json")
