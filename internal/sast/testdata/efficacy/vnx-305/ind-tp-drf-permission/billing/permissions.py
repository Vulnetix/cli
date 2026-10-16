from rest_framework.permissions import BasePermission


class HasServiceToken(BasePermission):
    message = "A service token is required."

    def has_permission(self, request, view):
~>        return bool(request.headers.get("Authorization"))
