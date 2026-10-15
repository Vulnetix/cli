from django.urls import path, re_path

from . import views

urlpatterns = [
    path("cart/", views.cart, name="cart"),
    re_path(r"^checkout/$", views.checkout, name="checkout"),
    path("account/", views.account, name="account"),
~>    re_path(r"^checkout/$", views.checkout_v2, name="checkout-v2"),
]
