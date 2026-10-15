import re



def safe_next(url):
~>    if re.match(r"^https?://accounts.example.com/", url):
        return url
    return "/"


~>TRUSTED = re.compile(r"^https://(www.)?shop.example.com/")
