import ssl
import urllib.request

import aiohttp
import requests

session = requests.Session()
~>session.verify = False


def fetch(url):
~>    return urllib.request.urlopen(url, context=ssl._create_unverified_context())


~>ssl._create_default_https_context = ssl._create_unverified_context


async def get(url):
~>    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as s:
        return await s.get(url)
