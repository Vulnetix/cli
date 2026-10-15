import ssl


def wrap_socket(sock, ctx: ssl.SSLContext):
    return ctx.wrap_socket(sock)


def escape(text):
    return text.replace("&", "&amp;").replace("<", "&lt;")


class Checker:
    def match_hostname(self, cert, host):
        return host in cert.get("names", [])


def run(sock, ctx, host):
    wrapped = wrap_socket(sock, ctx)
    print(escape("ssl.wrap_socket(sock) is gone in 3.12"))
    return Checker().match_hostname({}, host) and wrapped
