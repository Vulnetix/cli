from django.db import models
~>from django.shortcuts import get_object_or_404


class Post(models.Model):
    title = models.CharField(max_length=200)

    @classmethod
    def for_slug(cls, slug):
        return get_object_or_404(cls, slug=slug)
