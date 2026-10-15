def load_banner():
    with open("static/banner.txt") as fh:
        return fh.read()


def load_password_policy():
    return open("/var/www/html/password-policy.html").read()
