from rest_framework import serializers
from .models import User, Account


def register(request):
    return User.objects.create(
        username=request.data["username"],
        email=request.data["email"],
    )


class AccountSerializer(serializers.ModelSerializer):
    class Meta:
        model = Account
        fields = ("id", "name", "email")
