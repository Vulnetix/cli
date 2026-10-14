import socket
import ssl
import urllib.request

import aiohttp
import urllib3


def client_context():
    ctx = ssl.create_default_context()
~>    ctx.check_hostname = False
~>    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def open_unverified(url):
~>    ctx = ssl._create_unverified_context()
    return urllib.request.urlopen(url, context=ctx)


~>ssl._create_default_https_context = ssl._create_unverified_context

~>pool = urllib3.PoolManager(cert_reqs="CERT_NONE", assert_hostname=False)


def wrap(host):
    raw = socket.create_connection((host, 443))
~>    return ssl.wrap_socket(raw, cert_reqs=ssl.CERT_NONE)


async def fetch(url):
~>    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        async with session.get(url) as resp:
            return await resp.text()
