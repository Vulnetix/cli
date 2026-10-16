from django.urls import include, path

urlpatterns = [
    path("api/", include("billing.urls")),
    path("api/", include("accounts.urls")),
    path("health/", lambda r: None),
]
