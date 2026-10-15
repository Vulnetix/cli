from django.db import connection, models


class UserManager(models.Manager):
    def by_name(self, name):
        with connection.cursor() as cursor:
            cursor.execute("SELECT id FROM auth_user WHERE username = %s", [name])
            return cursor.fetchone()

    def raw_active(self):
        return self.raw("SELECT * FROM auth_user WHERE is_active")
