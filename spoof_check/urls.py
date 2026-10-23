from django.urls import path
from . import views

urlpatterns = [
    path("spoofcheck/", views.spoof_check, name="spoof_check"),
]
