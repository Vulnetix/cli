from django.urls import path
from django.views.decorators.csrf import csrf_exempt

from . import views

urlpatterns = [
    path("", views.index, name="index"),
~>    path("cart/add/", csrf_exempt(views.add_to_cart), name="cart-add"),
~>    path("hook/", csrf_exempt(views.PaymentHook.as_view())),
]
