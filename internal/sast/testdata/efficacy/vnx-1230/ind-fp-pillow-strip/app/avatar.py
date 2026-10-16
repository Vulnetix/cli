from PIL import Image
from flask import request


def upload_avatar():
    f = request.files["avatar"]
    img = Image.open(f.stream)
    clean = Image.new(img.mode, img.size)
    clean.putdata(list(img.getdata()))
    clean.save("static/avatars/me.png")
    return "ok"
