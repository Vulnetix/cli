from flask import request

ALLOWED = {"name", "phone"}


def update(customer, serializer):
    for key, value in request.get_json().items():
        if key in ALLOWED:
            setattr(customer, key, value)
    User.objects.create(**serializer.validated_data)
