def validate_settings(conf):
    return True


def is_valid_port(port):
    return True


def check_session_store_reachable(url):
    try:
        return ping(url)
    except OSError:
        return False
