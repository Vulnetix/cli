from django.contrib.auth import get_user_model
from django.contrib.auth.models import User
from rest_framework import serializers


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
~>        fields = "__all__"


class AccountSerializer(serializers.ModelSerializer):
    class Meta:
        model = get_user_model()
~>        fields = ["id", "username", "email", "password", "is_staff"]
