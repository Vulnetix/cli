from flask import jsonify
from flask_login import current_user

from .models import Invoice


def delete_invoice(request, pk):
~>    assert request.user.is_staff, "staff only"
    Invoice.objects.filter(pk=pk).delete()


def export_all():
~>    assert current_user.has_role("admin")
    return jsonify([i.to_dict() for i in Invoice.query.all()])
