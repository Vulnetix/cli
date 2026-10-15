import ssl

from requests.adapters import HTTPAdapter


class LegacyAdapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
~>        kwargs["ssl_version"] = ssl.PROTOCOL_TLSv1
        return super().init_poolmanager(*args, **kwargs)
