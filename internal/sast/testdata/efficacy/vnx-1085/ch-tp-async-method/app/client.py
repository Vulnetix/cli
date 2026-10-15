class Client:
~>    async def fetch(self, url):
        # resp = await self.session.get(url, timeout=5)
        # resp.raise_for_status()
        # data = await resp.json()
        resp = await self.session.get(url)
        # try:
        #     self.cache[url] = resp
        # except KeyError:
        #     pass
        return resp
