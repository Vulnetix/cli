import io

from flask import Blueprint, request, abort
from PIL import Image, ImageOps

bp = Blueprint("avatar", __name__)


@bp.post("/me/avatar")
def set_avatar():
    upload = request.files.get("avatar")
    if upload is None or not upload.mimetype.startswith("image/"):
        abort(400)
    img = ImageOps.exif_transpose(Image.open(upload.stream)).convert("RGB")
    img.thumbnail((512, 512))
    out = io.BytesIO()
    img.save(out, format="JPEG", quality=88)
    store_avatar(request.user_id, out.getvalue())
    return "", 204
