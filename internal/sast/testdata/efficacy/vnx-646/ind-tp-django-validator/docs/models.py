from django.core.validators import FileExtensionValidator
from django.db import models

class Document(models.Model):
    file = models.FileField(
~>        validators=[FileExtensionValidator(allowed_extensions=["pdf", "docx"])]
    )
