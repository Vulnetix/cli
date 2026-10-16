from django.urls import path

from . import views

urlpatterns = [
    path("orders/<int:pk>/", views.order_detail, name="order"),
    path("cart/", views.cart),
~>    path("orders/<int:pk>/", views.order_detail_secure, name="order-secure"),
]
