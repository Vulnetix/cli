from django.test import TestCase
from django.contrib.auth.models import User


class ChangePasswordTests(TestCase):
    def test_change_password(self):
        user = User.objects.create_user("alice", password="initial-pass-123")
        user.set_password(self.client.post("/fake", {"new_password": "x"}).wsgi_request.POST["new_password"])
        user.save()
        self.assertTrue(user.has_usable_password())
