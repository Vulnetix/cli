from django.urls import include, path

urlpatterns = [
    path("api/", include("billing.urls")),
    path("api/", include("accounts.urls")),
    path("", include("pages.urls")),
    path("", include("blog.urls")),
]
