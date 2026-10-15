from django.urls import re_path
from django.views.static import serve

urlpatterns = [
~>    re_path(r"^media/(?P<path>.*)$", serve, {"document_root": settings.MEDIA_ROOT, "show_indexes": True}),
]
