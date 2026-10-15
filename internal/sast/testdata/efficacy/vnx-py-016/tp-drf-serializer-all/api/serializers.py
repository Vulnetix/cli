from django import forms
from rest_framework import serializers

from .models import Customer


class CustomerSerializer(serializers.ModelSerializer):
    class Meta:
        model = Customer
~>        fields = "__all__"


class CustomerForm(forms.ModelForm):
    class Meta:
        model = Customer
~>        fields = '__all__'
