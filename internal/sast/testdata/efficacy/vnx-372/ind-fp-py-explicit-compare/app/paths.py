from bs4 import BeautifulSoup


def is_static(path: str) -> bool:
    if not path.find("/static"):
        return True
    return path.find("/assets/") != -1


def has_token(header: str) -> bool:
    return "Bearer" in header


def first_title(html: str):
    soup = BeautifulSoup(html, "html.parser")
    if soup.find("title"):
        return soup.find("title").text
    return None


def position(s: str, needle: str) -> int:
    pos = s.find(needle)
    if pos >= 0:
        return pos
    # if s.find(needle): is the buggy form
    return -1
