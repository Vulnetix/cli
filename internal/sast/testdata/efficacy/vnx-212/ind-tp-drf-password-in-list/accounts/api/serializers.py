from rest_framework import serializers

from accounts.models import Account


class AccountSerializer(serializers.ModelSerializer):
    class Meta:
        model = Account
~>        fields = ["id", "email", "username", "password", "date_joined"]
