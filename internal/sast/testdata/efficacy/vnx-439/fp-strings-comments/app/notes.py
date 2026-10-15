# hmac.new(key, msg) used MD5 before 3.8
# ctx = ssl.SSLContext()
HELP = "do not call ssl.wrap_socket(sock) or cgi.escape(s); hmac.new(k, m) needs digestmod"


def describe():
    return 'ssl.SSLContext() is deprecated'
