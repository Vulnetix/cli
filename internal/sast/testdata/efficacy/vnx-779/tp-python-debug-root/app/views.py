import logging

from django.shortcuts import render

~>logging.basicConfig(level=logging.DEBUG, filename="app.log")
log = logging.getLogger(__name__)


def index(request):
    return render(request, "index.html")
