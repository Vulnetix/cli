import requests


class Crawler:
    def __init__(self):
        self.http = requests.Session()
~>        self.http.verify = False
        self.http.headers["User-Agent"] = "crawler/1.0"

    def get(self, url):
        return self.http.get(url)
