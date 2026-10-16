from bs4 import BeautifulSoup


def cached_title(cache, html, key):
    hit = cache.get(key)
    if hit is not None:
        return hit
    soup = BeautifulSoup(html, "html.parser")
    title = soup.find("title").text
    cache.set(key, title)
    return title
