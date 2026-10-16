from django.conf import settings
from django.urls import path, re_path
from django.views.static import serve

from . import views

urlpatterns = [
    path("", views.home, name="home"),
~>    re_path(r"^media/(?P<path>.*)$", serve, {"document_root": settings.MEDIA_ROOT, "show_indexes": True}),
]
