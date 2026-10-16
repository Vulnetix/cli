from django.db import models


class Profile(models.Model):
    email = models.EmailField(unique=True)
~>    role = models.CharField(max_length=20, default="admin")
    created = models.DateTimeField(auto_now_add=True)
