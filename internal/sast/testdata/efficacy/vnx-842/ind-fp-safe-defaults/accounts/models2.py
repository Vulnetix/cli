from django.db import models


class Member(models.Model):
    role = models.CharField(max_length=20, default="member")
    is_staff = models.BooleanField(default=False)
    # note: do not default role to "admin" here
    label = "default=\"admin\" would be wrong"
