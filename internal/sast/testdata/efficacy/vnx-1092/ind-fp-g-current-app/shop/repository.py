from flask import g, current_app
from django.urls import reverse


def get_conn():
    if "db" not in g:
        g.db = connect(current_app.config["DATABASE"])
    return g.db


def absolute(pk):
    return reverse("order-detail", args=[pk])
