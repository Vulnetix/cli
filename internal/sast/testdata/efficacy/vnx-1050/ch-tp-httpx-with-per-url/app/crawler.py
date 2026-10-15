import httpx


def fetch_all(urls):
    pages = []
    for url in urls:
~>        with httpx.Client(timeout=10.0, follow_redirects=True) as client:
            pages.append(client.get(url).text)
    return pages
