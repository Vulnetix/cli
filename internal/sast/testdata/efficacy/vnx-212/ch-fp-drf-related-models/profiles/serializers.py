from rest_framework import serializers

from .models import UserProfile, AccountActivity


class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = "__all__"


class AccountActivitySerializer(serializers.ModelSerializer):
    class Meta:
        model = AccountActivity
        fields = "__all__"
