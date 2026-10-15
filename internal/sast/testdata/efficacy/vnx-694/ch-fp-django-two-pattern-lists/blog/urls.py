from django.urls import include, path

from . import api, views

api_patterns = [
    path("", api.index, name="api-index"),
    path("posts/", api.posts, name="api-posts"),
]

urlpatterns = [
    path("", views.index, name="index"),
    path("posts/", views.posts, name="posts"),
    path("api/", include(api_patterns)),
]
