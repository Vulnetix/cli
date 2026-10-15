from flask import request
from PIL import Image


def avatar():
    f = request.files["avatar"]
    img = Image.open(f.stream)
    img = img.convert("RGB")
    img.save("static/avatars/me.jpg", format="JPEG")
    return "", 201
