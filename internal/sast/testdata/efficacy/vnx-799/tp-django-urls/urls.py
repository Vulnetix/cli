from django.urls import path, re_path

from . import views

urlpatterns = [
~>    path("accounts/login/", views.login_view, name="login"),
~>    re_path(r"^otp/verify/$", views.verify_otp, name="otp"),
    path("accounts/profile/", views.profile, name="profile"),
]
