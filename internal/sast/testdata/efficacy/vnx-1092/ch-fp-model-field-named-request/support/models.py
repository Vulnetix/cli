from django.db import models
from flask_sqlalchemy import SQLAlchemy


class SupportRequest(models.Model):
    subject = models.CharField(max_length=120)
    body = models.TextField()


class Reply(models.Model):
    request = models.ForeignKey(SupportRequest, on_delete=models.CASCADE)

    def subject(self):
        return self.request.subject
