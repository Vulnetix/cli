from django.db import models


class Timestamped(models.Model):
    created = models.DateTimeField(auto_now_add=True)

    class Meta:
        abstract = True


class Publishable(models.Model):
    published = models.BooleanField(default=False)

    class Meta:
        abstract = True


class Article(Timestamped, Publishable):
    title = models.CharField(max_length=200)
