from django.contrib.auth.decorators import login_required
from django.urls import path

from . import views

urlpatterns = [
    path("orders/<int:pk>/cancel/", views.cancel_order),
    path("orders/<int:pk>/delete/", views.delete_my_order),
    path("orders/<int:pk>/items/clear/", login_required(views.remove_item)),
]
