from django import forms
from django.core.validators import FileExtensionValidator


class ContractUploadForm(forms.Form):
    title = forms.CharField(max_length=200)
    attachment = forms.FileField(
~>        validators=[FileExtensionValidator(allowed_extensions=["pdf", "docx"])],
        help_text="PDF or Word documents only",
    )
