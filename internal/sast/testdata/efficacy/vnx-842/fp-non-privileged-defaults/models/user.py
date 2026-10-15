from django.db import models


class Member(models.Model):
    role = models.CharField(max_length=20, default="viewer", choices=[("admin", "Admin"), ("viewer", "Viewer")])
    is_staff = models.BooleanField(default=False)
    is_admin = models.BooleanField(default=False)
    admin_notes = models.TextField(default="")
