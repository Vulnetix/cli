from rest_framework.permissions import BasePermission


class HasServiceToken(BasePermission):
    def has_permission(self, request, view):
~>        if request.META.get("HTTP_X_SERVICE_TOKEN"):
            return True
        return False
