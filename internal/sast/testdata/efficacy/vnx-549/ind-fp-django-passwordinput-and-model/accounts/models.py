from django.db import models


class Account(models.Model):
    username = models.CharField(max_length=150, unique=True)
    password = models.CharField(max_length=128)
