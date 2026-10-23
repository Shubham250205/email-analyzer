from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path("admin/", admin.site.urls),
    path("", include("email_parser.urls")),
    path("", include("dns_check.urls")),
    path("", include("spoof_check.urls")),
]
