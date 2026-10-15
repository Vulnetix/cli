from django.db import models
from django.urls import reverse

# Never import from django.http here; views own request.GET handling.


class Post(models.Model):
    slug = models.SlugField()

    def get_absolute_url(self):
        return reverse("post-detail", args=[self.slug])

    def describe(self):
        return "built from request.GET in the view"
