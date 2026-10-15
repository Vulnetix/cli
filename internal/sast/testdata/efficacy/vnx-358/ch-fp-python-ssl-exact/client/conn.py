import ssl


def verify_hostname(cert, hostname):
    ssl.match_hostname(cert, hostname)
    return hostname.endswith(".internal") or True


def check_server_host(server_host, allowed_hosts):
    ctx = ssl.create_default_context()
    if server_host not in allowed_hosts:
        raise ValueError("unknown host")
    return ctx.wrap_socket(socket.socket(), server_hostname=server_host)
