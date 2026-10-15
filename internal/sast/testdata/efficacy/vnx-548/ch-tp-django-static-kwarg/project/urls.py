from django.conf import settings
from django.conf.urls.static import static
from django.urls import path

from . import views

urlpatterns = [
    path("", views.index),
~>] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT, show_indexes=True)
