import textwrap


def write_config(path):
    template = textwrap.dedent("""
        # listen = 80
        # server_name = example.com
        # root = /var/www
        # index = index.html
        # gzip = on
        # access_log = /var/log/nginx/access.log
    """)
    with open(path, "w") as f:
        f.write(template)
