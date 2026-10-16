import requests


class StatusScraper:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "status-bot/1.0"})

    def fetch_banner(self):
        resp = self.session.get(self.base_url + "/banner.txt", timeout=5)
~>        banner = resp.text.strip()
        return banner
