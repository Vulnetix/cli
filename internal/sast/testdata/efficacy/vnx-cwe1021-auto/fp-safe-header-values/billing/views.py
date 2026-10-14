from django.shortcuts import render
from django.views.decorators.clickjacking import xframe_options_deny, xframe_options_sameorigin
from flask_talisman import Talisman


@xframe_options_sameorigin
def preview(request):
    return render(request, "billing/preview.html")


@xframe_options_deny
def confirm(request):
    response = render(request, "billing/confirm.html")
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    return response


def secure(app):
    Talisman(app, frame_options="DENY")
