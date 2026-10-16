import logging

from flask import Blueprint, request

from .models import Document

bp = Blueprint("feedback", __name__)
log = logging.getLogger(__name__)


@bp.route("/feedback", methods=["POST"])
def feedback():
    message = request.form.get("message", "")
    with open("/var/log/app/feedback.log", "a") as fh:
        fh.write(message + "\n")
    log.info("feedback for path %s", request.args.get("path"))
    doc = Document.objects.get(slug=request.args.get("slug"))
    return {"doc": doc.title}
