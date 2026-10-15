from rest_framework.permissions import BasePermission


class HasServiceToken(BasePermission):
    def has_permission(self, request, view):
~>        return bool(request.headers.get("Authorization"))
