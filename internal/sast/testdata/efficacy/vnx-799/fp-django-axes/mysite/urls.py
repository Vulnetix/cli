from django.contrib.auth import views as auth_views
from django.urls import path

urlpatterns = [
    path("accounts/login/", auth_views.LoginView.as_view(), name="login"),
]
