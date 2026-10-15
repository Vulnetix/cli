import requests

WEBHOOK = "https://hooks.example.com/notify"


def notify_all(events):
    for event in events:
~>        session = requests.Session()
        session.post(WEBHOOK, json=event.to_dict(), timeout=10)


async def fetch_all(urls):
    import aiohttp
    results = []
    for url in urls:
~>        async with aiohttp.ClientSession() as s:
            async with s.get(url) as resp:
                results.append(await resp.text())
    return results
