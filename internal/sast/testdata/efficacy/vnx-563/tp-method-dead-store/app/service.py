class Service:
    def handle(self, request):
~>        result = self.validate(request)
        result = self.process(request)
        return result

    async def fetch(self, client, url):
~>        response = await client.get(url)
        response = await client.get(url, timeout=5)
        return response.json()
