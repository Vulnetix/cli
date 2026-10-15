from django.db import models
~>from django.http import Http404
~>from django.shortcuts import redirect


class Post(models.Model):
    title = models.CharField(max_length=200)

    @classmethod
    def for_request(cls, request):
~>        slug = request.GET.get("slug")
        try:
            return cls.objects.get(slug=slug)
        except cls.DoesNotExist:
            raise Http404("missing")
