import pymysql
from app.models import User


class UsersController:
    def index(self, request):
        return User.objects.all()

    def search(self, request):
        term = request.GET.get("q", "")
~>        return User.objects.raw("SELECT * FROM users WHERE name LIKE %s", [term])

    def legacy(self, request):
~>        conn = pymysql.connect(host="db", user="app")
        return conn
