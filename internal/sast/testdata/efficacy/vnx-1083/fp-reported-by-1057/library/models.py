from django.db import models


class Book(models.Model):
    title = models.CharField(max_length=200)
    author_id = models.IntegerField()
    shelf = models.CharField(max_length=20)
