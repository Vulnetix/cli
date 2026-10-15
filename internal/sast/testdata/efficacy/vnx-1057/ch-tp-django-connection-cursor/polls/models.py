from django.db import models


class Question(models.Model):
    text = models.CharField(max_length=200)
    votes = models.IntegerField(default=0)
