from bs4 import BeautifulSoup


def clean(html):
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup.find_all("script"):
        tag.extract()
    return soup
