def parse_cookie_header(raw):
    cookies = {}
    for chunk in raw.split(";"):
        if not chunk.strip():
            continue
~>        name, value = map(str.strip, chunk.split("="))
        cookies[name] = value
    return cookies


def load_dotenv(path):
    with open(path, encoding="utf-8") as fh:
        lines = [l.strip() for l in fh if l.strip() and not l.startswith("#")]
~>    return dict(line.split("=") for line in lines)
