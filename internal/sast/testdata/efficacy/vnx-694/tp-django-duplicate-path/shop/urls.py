from django.urls import path, re_path

from . import views

urlpatterns = [
    path("orders/<int:pk>/", views.order_detail, name="order-detail"),
    path("orders/export/", views.export_orders),
~>    path("orders/<int:pk>/", views.order_detail_secure, name="order-detail-secure"),
    re_path(r"^legacy/(?P<pk>\d+)/$", views.legacy),
~>    re_path(r'^legacy/(?P<pk>\d+)/$', views.legacy_v2),
]
