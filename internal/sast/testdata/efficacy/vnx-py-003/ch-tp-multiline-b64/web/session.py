import base64
import pickle as pkl


def read_session(request):
    raw = request.cookies.get("session", "")
~>    data = pkl.loads(
        base64.b64decode(raw)
    )
    return data
