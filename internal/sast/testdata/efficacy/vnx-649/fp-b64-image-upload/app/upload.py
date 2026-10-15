import base64


def upload_avatar(request):
    data = base64.b64decode(request.json["image"])
    with open("/srv/avatars/x.png", "wb") as fh:
        fh.write(data)
    config = json.loads(open("config.json").read())
    return config
