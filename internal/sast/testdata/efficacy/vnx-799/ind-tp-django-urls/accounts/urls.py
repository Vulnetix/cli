from django.urls import path
from . import views

urlpatterns = [
    path("profile/", views.profile, name="profile"),
~>    path("accounts/login/", views.login_view, name="login"),
]
