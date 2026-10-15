import base64


def keep(store, form):
    raw = form["password"].encode("utf-8")
~>    store["pw"] = base64.b64encode(raw)


def keep_long(store, admin_password):
~>    store["admin"] = base64.b64encode(
        admin_password.encode()
    )
