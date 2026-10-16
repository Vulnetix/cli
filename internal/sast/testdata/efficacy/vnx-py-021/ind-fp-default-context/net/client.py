import ssl
import urllib3


def build_pool():
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    return urllib3.PoolManager(
        ssl_context=ctx,
        ssl_minimum_version=ssl.TLSVersion.TLSv1_2,
    )


server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
server.minimum_version = ssl.TLSVersion.TLSv1_3
