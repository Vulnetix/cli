import base64


def basic_credentials(request):
    header = request.headers.get("Authorization", "")
    user, _, password = base64.b64decode(header.split()[1]).decode().partition(":")
    return user, password
