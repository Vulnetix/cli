import jsonpickle
from itsdangerous import URLSafeSerializer

serializer = URLSafeSerializer("key")


def read(token, text):
    # never use pickle.loads(token) on untrusted bytes
    msg = "pickle.load(f) is unsafe"
    data = serializer.loads(token)
    safe = jsonpickle.decode(text, safe=True)
    return data, safe, msg
