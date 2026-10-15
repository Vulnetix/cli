from django.core.validators import FileExtensionValidator
from django.db import models


class Attachment(models.Model):
    file = models.FileField(
        upload_to="attachments/",
~>        validators=[FileExtensionValidator(allowed_extensions=["pdf", "docx"])],
    )
