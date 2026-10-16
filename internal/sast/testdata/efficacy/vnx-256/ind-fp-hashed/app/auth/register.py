from django.contrib.auth.hashers import make_password
from django.contrib.auth.models import User
from flask import request
from werkzeug.security import generate_password_hash

from app import db
from app.models import Member


def register_member():
    member = Member(email=request.form["email"])
    member.password = generate_password_hash(request.form["password"])
    db.session.add(member)
    db.session.commit()


def register_django(request):
    User.objects.create_user(username=request.POST["username"], password=request.POST["password"])
    raw = request.POST["password"]
    hashed = make_password(raw)
    Member.objects.create(email=request.POST["email"], password=hashed)
