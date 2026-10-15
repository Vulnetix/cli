import base64
import pickle


def profile(request):
    token = request.COOKIES.get("token")
    if token is None:
        return None
~>    raw = base64.b64decode(token)
    user = pickle.loads(raw)
    return user.is_admin
