from django.db import models


class ServiceAccount(models.Model):
    name = models.CharField(max_length=120)

    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return True

    def has_permission(self, perm):
        return True


class ApiPermission:
    def supports(self, method):
        return True
