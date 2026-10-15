import ssl


def connect(
    host,
    port=636,
~>    validate_certs=False,
    timeout=5.0,
) -> "Connection":
    ctx = ssl.create_default_context()
    return Connection(host, port, ctx, timeout)


def render(template,
           context,
~>           autoescape=False):
    return template.render(context)
